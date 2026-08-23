#!/usr/bin/env bash
#
# A real PostgreSQL server for `dotnet test`, on whatever this machine can run.
#
#   ./scripts/postgres.sh up       # start one, create the login, wait until it answers
#   ./scripts/postgres.sh status   # which backend, which version, reachable or not
#   ./scripts/postgres.sh down     # stop it, keep the data
#
# Why this exists
# ---------------
# `Boltway.Storage.PostgreSql.Tests` fails — it does not skip — when no server is reachable.
# That is deliberate and documented on `PostgresDatabase`: a storage suite that skips itself when
# the database is missing reads as green in exactly the situation where it measured nothing. The
# cost of that choice is that every machine which runs the suite needs a server, and before this
# script the only documented way to get one was Docker. Where there is no Docker daemon, that made
# SQLite the only relational implementation anyone ever actually ran, which is the wrong way round:
# PostgreSQL is what deploys.
#
# So: Docker when a daemon answers, a native cluster when one does not. Both paths end at the same
# host, port, role and password, which are also the ones `PostgresDatabase` defaults to and the ones
# the CI service container is configured with. One connection string across three environments.
#
# The version is pinned in one place below and used for both the image tag and the apt package, so
# local and CI cannot drift to different majors without someone editing this line.

set -euo pipefail

# Matches the `postgres:17-alpine` service container in .github/workflows/ci.yml and
# .github/workflows/publish-packages.yml. Change all three when changing this.
PG_VERSION="${BOLTWAY_PG_VERSION:-17}"
PG_PORT="${BOLTWAY_PG_PORT:-5432}"

# `PostgresDatabase.ServerConnectionString` defaults to exactly these. They are test credentials for
# a server bound to loopback; they are not a secret and there is no environment where this login
# reaches anything real.
PG_USER=boltway
PG_PASSWORD=boltway

CONTAINER_NAME=boltway-postgres

say() { printf '%s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# Docker only counts if the daemon answers. A present CLI with no daemon is the case this script was
# written for, and `command -v docker` alone would have picked the wrong path there.
have_docker() { command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; }

# Everything on the native path runs as the `postgres` system user.
as_postgres() {
    if [ "$(id -u)" -eq 0 ]; then
        su postgres -c "$1"
    elif command -v sudo >/dev/null 2>&1; then
        sudo -u postgres sh -c "$1"
    else
        die "need root or sudo to administer a native PostgreSQL cluster"
    fi
}

# Readiness is "a client can log in and run a statement", not "the port accepts a connection".
# pg_isready reports the latter, and on a cold container it is true for about a second before the
# server has finished creating the initial database.
wait_until_ready() {
    local deadline=$((SECONDS + 60))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if PGPASSWORD="$PG_PASSWORD" psql -h 127.0.0.1 -p "$PG_PORT" -U "$PG_USER" -d postgres \
            -tAc 'select 1' >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# ---------------------------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------------------------

docker_up() {
    if [ -n "$(docker ps -q --filter "name=^${CONTAINER_NAME}$")" ]; then
        say "docker: ${CONTAINER_NAME} already running"
    elif [ -n "$(docker ps -aq --filter "name=^${CONTAINER_NAME}$")" ]; then
        say "docker: starting existing ${CONTAINER_NAME}"
        docker start "$CONTAINER_NAME" >/dev/null
    else
        say "docker: running postgres:${PG_VERSION}-alpine as ${CONTAINER_NAME}"
        # POSTGRES_USER creates the role as superuser, so CREATE DATABASE is already permitted --
        # which the fixture needs, since it makes a database per test class.
        docker run --detach \
            --name "$CONTAINER_NAME" \
            --publish "127.0.0.1:${PG_PORT}:5432" \
            --env "POSTGRES_USER=${PG_USER}" \
            --env "POSTGRES_PASSWORD=${PG_PASSWORD}" \
            --env POSTGRES_DB=postgres \
            "postgres:${PG_VERSION}-alpine" >/dev/null
    fi
}

docker_down() {
    if [ -n "$(docker ps -q --filter "name=^${CONTAINER_NAME}$")" ]; then
        docker stop "$CONTAINER_NAME" >/dev/null
        say "docker: stopped ${CONTAINER_NAME} (data kept; 'docker rm ${CONTAINER_NAME}' to discard)"
    else
        say "docker: ${CONTAINER_NAME} is not running"
    fi
}

# ---------------------------------------------------------------------------------------------
# Native cluster
# ---------------------------------------------------------------------------------------------

native_install() {
    [ -x "/usr/lib/postgresql/${PG_VERSION}/bin/postgres" ] && return 0

    command -v apt-get >/dev/null 2>&1 || die \
        "PostgreSQL ${PG_VERSION} is not installed and this script only knows how to install it with apt-get.
Install it another way, or point the tests at an existing server:
  export BOLTWAY_TEST_POSTGRES='Host=…;Port=…;Username=…;Password=…;Maximum Pool Size=20'"

    export DEBIAN_FRONTEND=noninteractive

    # Ubuntu 24.04 ships PostgreSQL 16, so 17 comes from PGDG -- the project's own apt repository,
    # which is where the postgresql.org install instructions point. Added only when the version
    # asked for is not already available, so a machine whose archive carries it gains no extra
    # source.
    if ! apt-cache policy "postgresql-${PG_VERSION}" 2>/dev/null | grep -q 'Candidate: [0-9]'; then
        say "apt: PostgreSQL ${PG_VERSION} is not in the configured sources, adding PGDG"
        curl -fsS -o /usr/share/keyrings/pgdg.asc https://www.postgresql.org/media/keys/ACCC4CF8.asc
        local codename
        codename="$(. /etc/os-release && printf '%s' "$VERSION_CODENAME")"
        printf 'deb [signed-by=/usr/share/keyrings/pgdg.asc] https://apt.postgresql.org/pub/repos/apt %s-pgdg main\n' \
            "$codename" > /etc/apt/sources.list.d/pgdg.list
        apt-get update -qq
    fi

    say "apt: installing postgresql-${PG_VERSION}"
    apt-get install -y -qq "postgresql-${PG_VERSION}"
}

native_cluster_status() { pg_lsclusters -h 2>/dev/null | awk -v v="$PG_VERSION" '$1 == v && $2 == "main" { print $4 }'; }

native_up() {
    native_install

    if [ -z "$(native_cluster_status)" ]; then
        # The package's own postinst usually creates this, but it is skipped in images where
        # policy-rc.d denies service start, so do not assume it exists.
        say "cluster: creating ${PG_VERSION}/main on port ${PG_PORT}"
        pg_createcluster "$PG_VERSION" main --port "$PG_PORT" >/dev/null
    fi

    local configured_port
    configured_port="$(pg_lsclusters -h | awk -v v="$PG_VERSION" '$1 == v && $2 == "main" { print $3 }')"
    [ "$configured_port" = "$PG_PORT" ] || die \
        "cluster ${PG_VERSION}/main is configured for port ${configured_port}, not ${PG_PORT}.
Another cluster most likely holds ${PG_PORT}; 'pg_lsclusters' shows them all. Either drop it, or run
the tests against this one with BOLTWAY_TEST_POSTGRES=…Port=${configured_port}…"

    if [ "$(native_cluster_status)" != "online" ]; then
        say "cluster: starting ${PG_VERSION}/main"
        pg_ctlcluster "$PG_VERSION" main start
    else
        say "cluster: ${PG_VERSION}/main already online"
    fi

    # CREATEDB, not superuser: the fixture creates and drops a database per test class and needs
    # nothing beyond that. A test login that could read every other database on a developer's
    # machine is a cost with no matching benefit.
    #
    # Idempotent through DO rather than `createuser`, because this runs on every `up`.
    as_postgres "psql -qtAX -v ON_ERROR_STOP=1 -c \"
        DO \\\$\\\$ BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${PG_USER}') THEN
                CREATE ROLE ${PG_USER} LOGIN CREATEDB PASSWORD '${PG_PASSWORD}';
            ELSE
                ALTER ROLE ${PG_USER} LOGIN CREATEDB PASSWORD '${PG_PASSWORD}';
            END IF;
        END \\\$\\\$;\"" >/dev/null
}

native_down() {
    if [ "$(native_cluster_status)" = "online" ]; then
        pg_ctlcluster "$PG_VERSION" main stop
        say "cluster: stopped ${PG_VERSION}/main (data kept in /var/lib/postgresql/${PG_VERSION}/main)"
    else
        say "cluster: ${PG_VERSION}/main is not online"
    fi
}

# ---------------------------------------------------------------------------------------------

case "${1:-up}" in
    up)
        if have_docker; then docker_up; else
            say "docker: no daemon answers, using a native cluster"
            native_up
        fi

        command -v psql >/dev/null 2>&1 || die \
            "psql is not on PATH, so readiness cannot be verified. Install postgresql-client."

        wait_until_ready || die \
            "PostgreSQL did not accept a login as '${PG_USER}' on 127.0.0.1:${PG_PORT} within 60s"

        say ""
        say "ready: $(PGPASSWORD="$PG_PASSWORD" psql -h 127.0.0.1 -p "$PG_PORT" -U "$PG_USER" \
            -d postgres -tAc 'show server_version')  on 127.0.0.1:${PG_PORT} as ${PG_USER}"
        say ""
        say "This is what the tests use by default. Run them with:"
        say "    dotnet test Boltway.slnx"
        ;;

    down)
        if have_docker && [ -n "$(docker ps -aq --filter "name=^${CONTAINER_NAME}$")" ]; then
            docker_down
        else
            native_down
        fi
        ;;

    status)
        if have_docker; then
            say "docker daemon: yes"
            docker ps -a --filter "name=^${CONTAINER_NAME}$" \
                --format 'container: {{.Names}} {{.Image}} — {{.Status}}' >&2
        else
            say "docker daemon: no"
        fi

        if command -v pg_lsclusters >/dev/null 2>&1; then
            say "native clusters:"
            pg_lsclusters >&2
        else
            say "native clusters: postgresql-common is not installed"
        fi

        if command -v psql >/dev/null 2>&1 \
            && PGPASSWORD="$PG_PASSWORD" psql -h 127.0.0.1 -p "$PG_PORT" -U "$PG_USER" -d postgres \
                -tAc 'select 1' >/dev/null 2>&1; then
            say "127.0.0.1:${PG_PORT} as ${PG_USER}: reachable"
        else
            say "127.0.0.1:${PG_PORT} as ${PG_USER}: NOT reachable — run '$0 up'"
        fi
        ;;

    *)
        die "usage: $0 [up|down|status]"
        ;;
esac
