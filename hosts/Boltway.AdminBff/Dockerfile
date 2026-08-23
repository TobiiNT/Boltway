# The admin UI, as one image for every deployment.
#
# A second image rather than a second entrypoint on the authorization server's, and the reason is
# the reason this project exists at all: `N-17` says no admin endpoint may be reached with a cookie
# principal, so the UI has to be an OAuth client. Two processes that authenticate differently
# should not be one artifact that could be started with the wrong environment and become the other.
#
# Build context is the repository root, the same as the authorization server's and for the same
# reason: the `COPY` paths below are written from there, and it is what CI passes.
#
#   docker build -f hosts/Boltway.AdminBff/Dockerfile -t boltway-adminbff .

# A floating tag against a `global.json` written to accept whatever it moves to — see the note on
# the authorization server's Dockerfile, where a `latestPatch` pin met this tag moving a feature
# band and reddened `main` on a commit whose `test` job was green.
FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build

WORKDIR /src

# `.editorconfig` is a build input rather than an editor preference — see the note on the
# authorization server's Dockerfile, where leaving it out enforced a different analyser contract
# in the image than `dotnet test` enforced on the same commit.
#
# `src/` is copied even though this project references nothing in it, because `Directory.Build.props`
# and the restore graph are resolved across the tree. It costs a layer and buys a restore that
# behaves the same way here as it does locally.
COPY Directory.Build.props Directory.Packages.props global.json .editorconfig README.md ./
COPY src/ src/
COPY hosts/ hosts/
RUN dotnet restore hosts/Boltway.AdminBff/Boltway.AdminBff.csproj

RUN dotnet publish hosts/Boltway.AdminBff/Boltway.AdminBff.csproj \
    -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine

WORKDIR /app
ENV ASPNETCORE_URLS=http://+:8080 \
    DOTNET_RUNNING_IN_CONTAINER=true

COPY --from=build /app ./

RUN apk add --no-cache curl

# **No Data Protection volume, and that is a decision rather than an omission.**
#
# The authorization server mounts one because its cookie is a person's session with the deployment's
# identity provider, and signing everyone out on each deploy would be felt. This app's cookie is a
# key into an in-memory ticket store that a restart empties anyway — README's "the shipped store is
# in memory, which is the honest limit of it". Persisting the keys would preserve cookies whose
# tickets are gone, which is a worse failure than the redirect an operator gets today: they are
# bounced to the authorization server, are already signed in there, and come back.
#
# It is also what makes the second-replica warning in the README true rather than theoretical. If
# that store ever becomes shared, this decision is the one to revisit, in that order.
#
# The directory is still created and owned, though nothing mounts over it. Without it ASP.NET Core
# cannot write a key ring at all, falls back to keys held in memory, and says so at Warning on every
# boot — which is the correct behaviour arrived at by an error message, and this image would then
# log a line that reads like a defect on a deployment where nothing is wrong.
RUN mkdir -p /home/app/.aspnet/DataProtection-Keys \
    && chown -R $APP_UID:$APP_UID /home/app

USER $APP_UID
EXPOSE 8080

ARG BUILD_SHA=""
ENV BUILD_SHA=$BUILD_SHA

# And its ordered rendering: how many commits sit behind BUILD_SHA on the first-parent chain,
# from `git rev-list --count` in ci.yml. The sha identifies a build and orders nothing; the
# number orders builds and identifies nothing. Same provenance rule as the sha.
ARG BUILD_NUMBER=""
ENV BUILD_NUMBER=$BUILD_NUMBER

# Liveness only, and it deliberately does not reach the authorization server. A probe that failed
# while `AUTHORITY` was briefly unreachable would take this app out of rotation for a dependency it
# recovers from on its own — and during an incident on the authorization server, the admin UI is
# the thing an operator is trying to open.
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s \
  CMD curl -fsS http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["dotnet", "Boltway.AdminBff.dll"]
