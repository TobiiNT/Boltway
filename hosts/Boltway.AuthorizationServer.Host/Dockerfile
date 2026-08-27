# The authorization server, as one image for every deployment.
#
# Build context is the repository root. Every `COPY` below is written from there and it is what CI
# passes; a narrower context was worth having only while this tree was one directory of a larger
# repository, and it has been the root long enough that the paths below assume nothing else.
#
#   docker build -f hosts/Boltway.AuthorizationServer.Host/Dockerfile -t boltway-auth .

# A floating tag, and `global.json` has to be written to accept whatever it moves to.
#
# This is the second time this job went red on `main` after a green `test` job on the same commit,
# and the second time nobody had done anything: `sdk:10.0-alpine` moved from 10.0.302 to 10.0.400
# between the pull request's build and the merge's, `global.json` said `rollForward: latestPatch`,
# and 10.0.400 is a different feature band. The pull request had proved the image builds. It was
# proving it about an image that no longer existed.
#
# The pin was never what made the build reproducible - `latestPatch` already floated across
# 10.0.3xx. What it did was let the container and CI resolve *different* SDKs: the runner keeps
# several and satisfied the pin with 10.0.302, while the container has exactly one. `dotnet test`
# and this build then compiled the same source with two compilers, and only one of them said so.
# `latestFeature` is what makes them the same SDK again, which is the property the `.editorconfig`
# note below is also about.
#
# Pinning this tag to an exact SDK instead would work, but there is no `10.0.302-alpine` - only
# `10.0.302-alpine3.24` - so it would pin the OS release as a side effect of pinning the compiler,
# in two Dockerfiles, and stop the base image taking security updates.
FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build

WORKDIR /src

# Restore against the manifests alone, so a source-only change does not re-download the graph.
#
# `.editorconfig` is in this list because it is a build input, not an editor preference. It carries
# thirteen analyser severities for this tree, six of them raising a rule to `error` - ordinal string
# comparison, weak crypto, insecure randomness - and one lowering CA1848 to a suggestion on purpose.
# With TreatWarningsAsErrors set, a build that cannot see this file enforces a different contract
# than `dotnet test` does, in both directions at once.
#
# It was left out of this list once. The image build then failed on the rule this tree had
# deliberately relaxed, while silently not enforcing the six it had deliberately raised - and it
# failed on `main`, after a green `test` job on the same commit, because nothing built this
# Dockerfile before a merge.
COPY Directory.Build.props Directory.Packages.props global.json .editorconfig README.md ./
COPY src/ src/
COPY hosts/ hosts/
RUN dotnet restore hosts/Boltway.AuthorizationServer.Host/Boltway.AuthorizationServer.Host.csproj

RUN dotnet publish hosts/Boltway.AuthorizationServer.Host/Boltway.AuthorizationServer.Host.csproj \
    -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine

WORKDIR /app
ENV ASPNETCORE_URLS=http://+:8080 \
    DOTNET_RUNNING_IN_CONTAINER=true

# No ICU, deliberately. Directory.Build.props sets InvariantGlobalization for this tree -
# an authorization server compares issuers, resources and redirect URIs ordinally by design,
# so a culture-aware comparison is not a feature it is missing but a rule it is keeping.
COPY --from=build /app ./

RUN apk add --no-cache curl

# The Data Protection key ring - what encrypts the login cookie and the antiforgery token. ASP.NET
# Core puts it at $HOME/.aspnet/DataProtection-Keys, and left inside the container it dies with the
# container: every redeploy signs everyone out, and anyone mid-OAuth is bounced to /login by a
# redirect that names nothing, which reads exactly like the consent page looping.
#
# So a deployment mounts a volume here. This directory has to exist in the image for that to work,
# and that is the part worth knowing: **Docker copies ownership into a new named volume only from a
# path the image already has.** Created at runtime instead, the volume mounts owned by root, the
# server runs as $APP_UID, and it cannot write its own keys - the same symptom as having no volume
# at all, reached by a different route. The compose file used to carry a manual `docker volume
# create` plus a `chown` to work around exactly this.
#
# What this does not fix: the keys are unencrypted at rest, which the server says on every boot as
# "No XML encryptor configured". Persisting them trades a key that died with the container for a
# file on the host's disk. That is the right trade for a single-host deployment and it should stay
# a deliberate one.
RUN mkdir -p /home/app/.aspnet/DataProtection-Keys \
    && chown -R $APP_UID:$APP_UID /home/app

USER $APP_UID
EXPOSE 8080

# Which build this is, baked in at build time and reported by /health.
#
# It has to come from the image rather than from the deployment's own configuration, because the
# question it answers is "is the thing serving the thing we deployed" - and a value the deployment
# supplies answers that with its own opinion. An image can only claim the sha it was built from.
#
# Unset in a local `docker build` and that is fine: /health then omits the field rather than
# claiming a build it cannot know.
ARG BUILD_SHA=""
ENV BUILD_SHA=$BUILD_SHA

# And its ordered rendering: how many commits sit behind BUILD_SHA on the first-parent chain,
# from `git rev-list --count` in ci.yml. The sha identifies a build and orders nothing; the
# number orders builds and identifies nothing. Same provenance rule as the sha.
ARG BUILD_NUMBER=""
ENV BUILD_NUMBER=$BUILD_NUMBER

# Liveness, not readiness. /health touches no database: a probe that fails when Postgres blinks
# takes the whole server out of rotation for a dependency most requests here never reach.
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s \
  CMD curl -fsS http://127.0.0.1:8080/health || exit 1

# `migrate` and `new-key` are arguments to this same entrypoint, so the deploy job and the
# service run the byte-identical image. A migration applied by a different build than the one
# about to serve is how a schema and a binary disagree.
ENTRYPOINT ["dotnet", "Boltway.AuthorizationServer.Host.dll"]
