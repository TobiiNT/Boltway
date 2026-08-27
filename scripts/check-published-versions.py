#!/usr/bin/env python3
"""Refuse to skip a package whose version is already published but whose contents have moved.

    python3 scripts/check-published-versions.py <packages-dir> <feed-owner>

`dotnet nuget push --skip-duplicate` is what lets one run push the package whose version moved
without failing on the fifteen whose version did not. That is worth keeping - versions here are
per-package, not per-tag. What it cannot tell you is *why* a version is already there: "unchanged,
correctly skipped" and "changed, and the change is being dropped on the floor" are the same exit
code.

The second one shipped, and it is worth being exact about how far it got:

  - `Boltway.ResourceServer` stayed at 0.1.0 across the change that added
    `ProtectedResourceOptions.SigningKeySource`. The feed already held a 0.1.0 from an earlier run,
    so the push skipped it and the workflow was green.
  - `Boltway.Mcp` 0.4.0 was packed in the same run and *was* new, so it was pushed. It calls
    that setter, and a ProjectReference packs as a dependency on the referenced project's version -
    which was 0.1.0. So a package that needs the new assembly shipped depending on the old one.
  - The downstream connector then built green, and its image built green, because the C# compiler never
    checks a call that lives inside an already-compiled dependency.
  - It failed when the JIT resolved the method: `MissingMethodException` out of
    `JwksRefresher.StartAsync`, which throws out of `Host.StartAsync`, which exits the process. A
    container that restart-loops behind a 502, with the reason only in its own log.

Nothing between the source change and the outage was red. This step is the check that would have
been.

**Names, not bytes.** Two builds of the same source are not obliged to be byte-identical, and a
check that goes red on a rebuild is a check somebody switches off - which would leave this worse
than it is now. Every type, method and property name a .NET assembly defines or references is in
its metadata `#Strings` heap, so comparing the *set of names* catches a member that appeared or
vanished while staying quiet about a recompile. That is exactly the change that must not ship under
a version somebody has already restored.

Verified against the outage above and against a rebuild, which is the pair that matters:
`Boltway.ResourceServer 0.1.0` reports `get_SigningKeySource` and `set_SigningKeySource`
added, and `Boltway.Mcp 0.4.0` - the same source built twice, once here and once on a runner -
reports no change at all.

**And the nuspec's `<dependencies>`, because names alone miss the half of this that has no
assembly.** A ProjectReference packs as a dependency on the referenced project's version, so a
project whose own source never changed still needs a bump when something it references moves -
`Directory.Build.props` says exactly that, in the comment beside the number. When that bump is
forgotten the packed nuspec names a newer dependency while every assembly in the package is
byte-for-byte what is published: the name comparison above reports `unchanged`, the push skips, and
the corrected nuspec is dropped. What a consumer then restores is a package pinning a dependency
version that is merely old, and no amount of publishing the newer one can reach them.

That is the same outage as the one above seen from the other end. `Boltway.Mcp` was caught because
its own version was new; a sibling package that only *referenced* the changed project would not have
been caught by anything here at all. Comparing the element is cheap and exact - the nuspec is
generated, so it does not churn between two builds of the same source the way a metadata heap can.

Be clear about what that does not cover: a signature changed without any name changing - the same
member taking an `int` where it took a `long` - has the same names and passes here, and is still a
`MissingMethodException` for a consumer. Comparing full signatures needs a metadata reader rather
than a heap scan. This catches the two shapes that actually bit; it is not a compatibility checker.

Exits 1 if any package drifted, naming each one and what moved.
"""

import io
import os
import re
import struct
import sys
import urllib.error
import urllib.parse
import urllib.request
import base64
import zipfile
from xml.etree import ElementTree

def section_table(data, pe):
    """(virtual address, virtual size, raw offset) for each PE section, to resolve an RVA."""
    sections = struct.unpack_from('<H', data, pe + 6)[0]
    optional_size = struct.unpack_from('<H', data, pe + 20)[0]
    table = pe + 24 + optional_size
    out = []
    for i in range(sections):
        entry = table + i * 40
        virtual_size, virtual_address, _raw_size, raw_offset = struct.unpack_from(
            '<IIII', data, entry + 8)
        out.append((virtual_address, virtual_size, raw_offset))
    return out


def to_offset(sections, rva):
    """An RVA as a file offset, or None when it falls outside every section."""
    for virtual_address, virtual_size, raw_offset in sections:
        if virtual_address <= rva < virtual_address + virtual_size:
            return raw_offset + (rva - virtual_address)
    return None


def names(dll_bytes):
    """Every identifier an assembly defines or references, read from its `#Strings` heap.

    Not a scan for printable runs. That was tried first and is unusable: a compressed metadata
    table, a signature blob and an MVID all contain byte runs that are accidentally ASCII, so two
    builds of *identical source* differed by dozens of "names" like `&~A` and `*.s`. Everything
    would have been flagged, which is the same as nothing being flagged.

    The `#Strings` heap is the real thing - NUL-separated UTF-8, holding every type, method,
    property, field, namespace and referenced-assembly name, and nothing else. Walking the PE to
    reach it is a fixed sequence: the CLI header lives in data directory 14, the metadata root at
    its offset 8, and the stream headers follow the version string.

    Returns an empty set for anything that is not a managed assembly, and the caller treats that as
    "nothing to compare" rather than as a difference - a native or resource-only DLL has no API
    surface this can speak about, and inventing one would be the failure this repository's own
    LESSONS.md is about.
    """
    try:
        if dll_bytes[:2] != b'MZ':
            return set()
        pe = struct.unpack_from('<I', dll_bytes, 0x3c)[0]
        if dll_bytes[pe:pe + 4] != b'PE\0\0':
            return set()

        magic = struct.unpack_from('<H', dll_bytes, pe + 24)[0]
        # PE32 puts 16 directories at optional-header offset 96; PE32+ at 112.
        directories = pe + 24 + (96 if magic == 0x10b else 112)
        cli_rva = struct.unpack_from('<I', dll_bytes, directories + 14 * 8)[0]
        if cli_rva == 0:
            return set()

        sections = section_table(dll_bytes, pe)
        cli = to_offset(sections, cli_rva)
        if cli is None:
            return set()

        metadata_rva = struct.unpack_from('<I', dll_bytes, cli + 8)[0]
        root = to_offset(sections, metadata_rva)
        if root is None or dll_bytes[root:root + 4] != b'BSJB':
            return set()

        version_length = struct.unpack_from('<I', dll_bytes, root + 12)[0]
        cursor = root + 16 + version_length          # version string, already 4-byte padded
        stream_count = struct.unpack_from('<H', dll_bytes, cursor + 2)[0]
        cursor += 4

        for _ in range(stream_count):
            offset, size = struct.unpack_from('<II', dll_bytes, cursor)
            end = dll_bytes.index(b'\0', cursor + 8)
            name = dll_bytes[cursor + 8:end]
            cursor = (end + 1 + 3) & ~3              # names are padded to a 4-byte boundary
            if name == b'#Strings':
                heap = dll_bytes[root + offset:root + offset + size]
                # Only what a consumer could bind to. The heap also holds every compiler-generated
                # name - `<PrivateImplementationDetails>`, `<>c__DisplayClass10_0`,
                # `<Prop>k__BackingField`, `<Method>d__6` - and those churn for reasons that are
                # not API changes: closure classes are numbered in source order, so editing a
                # method body renumbers the ones after it. Measured on two builds of identical
                # source, that alone produced a difference and would have failed this check on
                # every rebuild.
                #
                # `<` and `>` are the whole filter, and they are exact rather than heuristic: the
                # CLR permits them in metadata names and C# does not, which is precisely why the
                # compiler uses them for names it does not want anybody binding to. What is left is
                # the set a `MissingMethodException` can be about - and the members that caused
                # this one, `get_SigningKeySource` and `set_SigningKeySource`, survive the filter.
                return {
                    s for s in heap.split(b'\0')
                    if s and b'<' not in s and b'>' not in s
                }

        return set()
    except (struct.error, ValueError, IndexError):
        # Unreadable is not the same as unchanged, and this must not quietly pass. Raising keeps
        # the decision with the caller, which fails the check rather than skipping the package.
        raise


def assemblies(nupkg_bytes):
    """Every lib/ assembly in a package, keyed by its path inside the package."""
    with zipfile.ZipFile(io.BytesIO(nupkg_bytes)) as z:
        return {
            n: z.read(n)
            for n in z.namelist()
            if n.startswith('lib/') and n.endswith('.dll')
        }


def local(tag):
    """An element's name without its XML namespace.

    The nuspec schema URL carries a year in it and has been revised more than once, so matching
    `{http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd}dependency` would be matching the
    version of the schema NuGet happened to emit under. The local name is the stable half.
    """
    return tag.rsplit('}', 1)[-1]


def dependencies(nupkg_bytes):
    """Every dependency the nuspec declares, as sorted `<framework> | <id> <range>` lines.

    Read from the nuspec rather than from the assemblies, because this is the part of a package that
    has no assembly: a ProjectReference becomes a `<dependency>` on the referenced project's
    version, and moving that version changes nothing about the bytes in `lib/`.

    Grouped by target framework and kept in the comparison, because a dependency that moved from one
    framework group to another is a real change to what a consumer resolves - flattening the groups
    would report that as no change at all.

    Returns an empty list for a package with no nuspec or no dependencies. Both compare equal to the
    same absence on the other side, which is what "nothing to say about this" has to mean here.
    """
    with zipfile.ZipFile(io.BytesIO(nupkg_bytes)) as archive:
        name = next((n for n in archive.namelist() if n.endswith('.nuspec')), None)
        if name is None:
            return []
        raw = archive.read(name)

    root = ElementTree.fromstring(raw)

    node = next((e for e in root.iter() if local(e.tag) == 'dependencies'), None)
    if node is None:
        return []

    found = []

    def record(framework, dependency):
        found.append(
            f'{framework} | {dependency.get("id", "?")} {dependency.get("version", "(any)")}'
        )

    for child in node:
        if local(child.tag) == 'group':
            # `targetFramework` is optional on a group and means "every framework not named by
            # another group". Spelling that absence as a word keeps it distinguishable from a group
            # that names a framework called nothing.
            framework = child.get('targetFramework') or '(all frameworks)'
            for dependency in child:
                if local(dependency.tag) == 'dependency':
                    record(framework, dependency)
        elif local(child.tag) == 'dependency':
            # The pre-group flat form. Still legal, still produced by older tooling, and a package
            # in the feed may well have been packed by some.
            record('(all frameworks)', child)

    return sorted(found)


def identity(nupkg_path):
    """The package id and version, read from the nuspec rather than parsed out of the filename.

    A filename split on the first digit gets `Boltway.OAuth.Tokens` wrong the day somebody
    ships a package with a digit in its name, and the nuspec is right there.
    """
    with zipfile.ZipFile(nupkg_path) as z:
        nuspec = next(n for n in z.namelist() if n.endswith('.nuspec'))
        xml = z.read(nuspec).decode('utf-8')
    pid = re.search(r'<id>([^<]+)</id>', xml).group(1)
    version = re.search(r'<version>([^<]+)</version>', xml).group(1)
    return pid, version


class DropAuthOnCrossHostRedirect(urllib.request.HTTPRedirectHandler):
    """Carry the credential to the feed and to nowhere else.

    GitHub Packages answers a download with a 302 to blob storage, where the authorization is a
    signature in the query string. urllib replays every header on a redirect by default, so the
    Authorization header arrives too and the storage account rejects the whole request - a 403 that
    reads exactly like a bad token. Measured: it is not; the same token works on the first hop.

    Dropping it is also the part worth keeping on purpose. A redirect is a target the feed chose,
    not one this script did, and a credential that follows a redirect anywhere is a credential
    handed to whoever can answer with a Location header.
    """

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        redirected = super().redirect_request(request, fp, code, msg, headers, newurl)
        if redirected is not None:
            same_host = urllib.parse.urlparse(newurl).netloc == urllib.parse.urlparse(
                request.full_url).netloc
            if not same_host:
                # Both spellings: urllib normalises header names it was given, and the one added
                # via `Request(headers=...)` keeps the capitalisation it arrived with.
                redirected.headers.pop('Authorization', None)
                redirected.headers.pop('authorization', None)
        return redirected


OPENER = urllib.request.build_opener(DropAuthOnCrossHostRedirect)


def fetch(url, auth_header=None):
    """The bytes at `url`, or None when the feed answers 404.

    404 is the answer that means "new"; anything else is raised, because a feed that cannot be read
    is not evidence that a version is absent - that is the whole failure mode this file exists to
    close, one layer up.
    """
    headers = {'Authorization': auth_header} if auth_header else {}
    request = urllib.request.Request(url, headers=headers)
    try:
        with OPENER.open(request, timeout=60) as response:
            return response.read()
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def published(owner, pid, version, auth_header):
    """Every feed that already holds this id and version, as (feed name, package bytes).

    **Both feeds, and nuget.org first, because they are not equally forgiving.** A version on
    GitHub Packages can be deleted; a version on nuget.org can only be unlisted, and unlisting does
    not free the number or un-restore it for anybody who already has it. Reading only the deletable
    one was this check measuring the cheap half: prune a version from GitHub Packages and the
    lookup answers 404, the caller prints `new`, the push goes to nuget.org where that version does
    exist, and `--skip-duplicate` drops it exactly as described at the top of this file.

    Both are flat-container URLs and both lowercase the id; nuget.org lowercases the version too,
    and needs no credential to read.
    """
    lower, lowver = pid.lower(), version.lower()

    feeds = [
        ('nuget.org',
         f'https://api.nuget.org/v3-flatcontainer/'
         f'{lower}/{lowver}/{lower}.{lowver}.nupkg',
         None),
        ('GitHub Packages',
         f'https://nuget.pkg.github.com/{owner}/download/'
         f'{lower}/{version}/{lower}.{version}.nupkg',
         auth_header),
    ]

    found = []
    for name, url, header in feeds:
        body = fetch(url, header)
        if body is not None:
            found.append((name, body))
    return found


def compare(fresh_assemblies, published_assemblies):
    """What moved between a packed assembly set and a published one, as readable lines."""
    changes = []
    for name in sorted(set(fresh_assemblies) | set(published_assemblies)):
        if name not in published_assemblies:
            changes.append(f'{name} is new in this build')
            continue
        if name not in fresh_assemblies:
            changes.append(f'{name} is in the feed and not in this build')
            continue
        added = names(fresh_assemblies[name]) - names(published_assemblies[name])
        removed = names(published_assemblies[name]) - names(fresh_assemblies[name])
        if added or removed:
            changes.append(
                f'{name}: {len(added)} name(s) added, {len(removed)} removed'
                + sample('added', added) + sample('removed', removed)
            )
    return changes


def dependency_changes(fresh, published):
    """What moved in the nuspec's `<dependencies>` element, as readable lines.

    Both sides are printed in full rather than as a count. A dependency drift is almost always one
    version number in one line, and the whole question a reader has is "from what, to what" - a
    summary saying `1 added, 1 removed` would make them download both packages to answer it.
    """
    added = sorted(set(fresh) - set(published))
    removed = sorted(set(published) - set(fresh))
    if not added and not removed:
        return []

    lines = ['the nuspec <dependencies> element has moved:']
    lines += [f'    in the feed:     {entry}' for entry in removed]
    lines += [f'    in this build:   {entry}' for entry in added]
    return lines


def main():
    if len(sys.argv) != 3:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2

    directory, owner = sys.argv[1], sys.argv[2]

    actor = os.environ.get('GITHUB_ACTOR', '')
    token = os.environ.get('GITHUB_TOKEN', '')
    if not token:
        print('::error::GITHUB_TOKEN is unset, so the feed cannot be read. This check cannot pass')
        print('::error::by default: an unreadable feed is not evidence that a version is unchanged.')
        return 1
    auth_header = 'Basic ' + base64.b64encode(f'{actor}:{token}'.encode()).decode()

    packages = sorted(
        os.path.join(directory, n) for n in os.listdir(directory) if n.endswith('.nupkg')
    )
    if not packages:
        print(f'::error::no .nupkg files in {directory} — nothing was packed, which is not a pass')
        return 1

    drifted = []
    for path in packages:
        pid, version = identity(path)
        existing = published(owner, pid, version, auth_header)

        if not existing:
            print(f'  new       {pid} {version}')
            continue

        with open(path, 'rb') as handle:
            fresh_package = handle.read()

        fresh_assemblies = assemblies(fresh_package)
        fresh_dependencies = dependencies(fresh_package)

        for feed, body in existing:
            # Two comparisons rather than one, because they catch different failures: the assemblies
            # catch a member that appeared or vanished, the nuspec catches a referenced version that
            # moved while every assembly stayed identical. A package can drift on either alone.
            changes = (compare(fresh_assemblies, assemblies(body))
                       + dependency_changes(fresh_dependencies, dependencies(body)))
            if changes:
                drifted.append((pid, version, feed, changes))
                print(f'  DRIFTED   {pid} {version} ({feed})')
            else:
                print(f'  unchanged {pid} {version} ({feed})')

    if not drifted:
        return 0

    print()
    for pid, version, feed, changes in drifted:
        print(f'::error::{pid} {version} is already on {feed} with different contents.')
        for change in changes:
            print(f'::error::  {change}')
        print(f'::error::  `--skip-duplicate` would drop this build and keep the published one, so')
        print(f'::error::  a consumer restoring {pid} {version} gets neither what is in the feed')
        print(f'::error::  nor what was just built — it gets the old one, silently, and finds out')
        print(f'::error::  at runtime. Bump the version instead.')
    return 1


def sample(label, values, limit=5):
    """A few of the names that moved. Enough to recognise the change, not enough to be a diff."""
    if not values:
        return ''
    shown = sorted(v.decode('utf-8', 'replace') for v in values)[:limit]
    more = f' (+{len(values) - limit} more)' if len(values) > limit else ''
    return f'; {label}: ' + ', '.join(shown) + more


if __name__ == '__main__':
    sys.exit(main())
