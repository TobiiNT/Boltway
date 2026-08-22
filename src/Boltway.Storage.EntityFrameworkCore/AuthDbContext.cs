using Boltway.Storage.EntityFrameworkCore.Entities;
using Microsoft.EntityFrameworkCore;

namespace Boltway.Storage.EntityFrameworkCore;

/// <summary>
/// The authorization server's schema.
/// </summary>
/// <remarks>
/// <para>
/// Public because a host has to name it — <c>AddDbContextFactory&lt;AuthDbContext&gt;</c>, and
/// <c>dotnet ef migrations</c> after that. The entity classes behind it are <see langword="internal"/>:
/// they are the shape of the tables, not an API, and the records in
/// <c>Boltway.AuthorizationServer.Abstractions</c> are what callers see.
/// </para>
/// <para>
/// <b>The stores do not use the change tracker for decisions.</b> Everything that has to be atomic
/// is a conditional <c>UPDATE</c> whose rows-affected is the answer, or a read inside a transaction
/// the provider opened for that purpose. <see cref="QueryTrackingBehavior.NoTracking"/> is the
/// default here so a stale first-level cache cannot answer a question the database was asked; the
/// two paths that do need tracked entities opt back in per query.
/// </para>
/// </remarks>
/// <param name="options">Provider and connection, supplied by the host.</param>
public class AuthDbContext(DbContextOptions<AuthDbContext> options) : DbContext(options)
{
    internal DbSet<AuthorizationCodeRow> AuthorizationCodes => Set<AuthorizationCodeRow>();

    internal DbSet<RefreshTokenRow> RefreshTokens => Set<RefreshTokenRow>();

    internal DbSet<RefreshTokenFamilyRow> RefreshTokenFamilies => Set<RefreshTokenFamilyRow>();

    internal DbSet<GrantRow> Grants => Set<GrantRow>();

    internal DbSet<ConsentRow> Consents => Set<ConsentRow>();

    internal DbSet<UserRow> Users => Set<UserRow>();

    internal DbSet<ExternalLoginRow> ExternalLogins => Set<ExternalLoginRow>();

    /// <summary>The append-only administrative audit log.</summary>
    internal DbSet<AdminAuditRow> AdminAudit => Set<AdminAuditRow>();

    /// <summary>Reset and verification links. S-47.</summary>
    internal DbSet<UserTokenRow> UserTokens => Set<UserTokenRow>();

    /// <summary>The roles a deployment defined.</summary>
    internal DbSet<RoleRow> Roles => Set<RoleRow>();

    /// <summary>Which accounts hold which of them.</summary>
    internal DbSet<UserRoleRow> UserRoles => Set<UserRoleRow>();

    /// <summary>Clients this deployment created. Never written on the CIMD path — A-08.</summary>
    internal DbSet<ClientRow> Clients => Set<ClientRow>();

    /// <summary>Client-assertion identifiers already used, so none is accepted twice. RFC 7523 §3.</summary>
    internal DbSet<ClientAssertionRow> ClientAssertions => Set<ClientAssertionRow>();

    /// <inheritdoc />
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        ArgumentNullException.ThrowIfNull(optionsBuilder);

        base.OnConfiguring(optionsBuilder);
        optionsBuilder.UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking);
    }

    /// <inheritdoc />
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<AuthorizationCodeRow>(entity =>
        {
            entity.ToTable("authorization_codes");
            entity.HasKey(e => e.CodeHash);
            entity.Property(e => e.CodeHash).HasColumnName("code_hash").HasMaxLength(32);
            entity.Property(e => e.GrantId).HasColumnName("grant_id").HasMaxLength(64);
            entity.Property(e => e.ClientId).HasColumnName("client_id").HasMaxLength(512);
            entity.Property(e => e.ClientIdKind).HasColumnName("client_id_kind");
            entity.Property(e => e.RedirectUriUsed).HasColumnName("redirect_uri_used").HasMaxLength(2048);
            entity.Property(e => e.CodeChallenge).HasColumnName("code_challenge").HasMaxLength(128);
            entity.Property(e => e.ChallengeMethod).HasColumnName("challenge_method");
            entity.Property(e => e.PkceWasRequested).HasColumnName("pkce_was_requested");
            entity.Property(e => e.Scope).HasColumnName("scope").HasMaxLength(2048);
            entity.Property(e => e.Resources).HasColumnName("resources").HasMaxLength(4096);
            entity.Property(e => e.Nonce).HasColumnName("nonce").HasMaxLength(512);
            entity.Property(e => e.AuthTime).HasColumnName("auth_time");
            entity.Property(e => e.IssuedAt).HasColumnName("issued_at");
            entity.Property(e => e.ExpiresAt).HasColumnName("expires_at");
            entity.Property(e => e.RedeemedAt).HasColumnName("redeemed_at");

            // The sweeper's predicate. It reads redeemed_at too, but expiry is the selective half:
            // an unredeemed code is the overwhelming majority of rows and is deleted the moment it
            // expires.
            entity.HasIndex(e => e.ExpiresAt).HasDatabaseName("ix_authorization_codes_expires_at");
        });

        modelBuilder.Entity<RefreshTokenRow>(entity =>
        {
            entity.ToTable("refresh_tokens");
            entity.HasKey(e => e.TokenHash);
            entity.Property(e => e.TokenHash).HasColumnName("token_hash").HasMaxLength(32);
            entity.Property(e => e.GrantId).HasColumnName("grant_id").HasMaxLength(64);
            entity.Property(e => e.FamilyId).HasColumnName("family_id").HasMaxLength(64);
            entity.Property(e => e.Generation).HasColumnName("generation");
            entity.Property(e => e.PredecessorHash).HasColumnName("predecessor_hash").HasMaxLength(32);
            entity.Property(e => e.SuccessorHash).HasColumnName("successor_hash").HasMaxLength(32);
            entity.Property(e => e.IssuedAt).HasColumnName("issued_at");
            entity.Property(e => e.ExpiresAt).HasColumnName("expires_at");
            entity.Property(e => e.ConsumedAt).HasColumnName("consumed_at");

            // RevokeFamilyAsync counts the unconsumed rows of one family.
            entity.HasIndex(e => e.FamilyId).HasDatabaseName("ix_refresh_tokens_family_id");
        });

        modelBuilder.Entity<RefreshTokenFamilyRow>(entity =>
        {
            entity.ToTable("refresh_token_families");
            entity.HasKey(e => e.FamilyId);
            entity.Property(e => e.FamilyId).HasColumnName("family_id").HasMaxLength(64);
            entity.Property(e => e.RevokedAt).HasColumnName("revoked_at");
        });

        modelBuilder.Entity<GrantRow>(entity =>
        {
            entity.ToTable("grants");
            entity.HasKey(e => e.GrantId);
            entity.Property(e => e.GrantId).HasColumnName("grant_id").HasMaxLength(64);
            entity.Property(e => e.Subject).HasColumnName("subject").HasMaxLength(64);
            entity.Property(e => e.ClientId).HasColumnName("client_id").HasMaxLength(512);
            entity.Property(e => e.ClientIdKind).HasColumnName("client_id_kind");
            entity.Property(e => e.Scope).HasColumnName("scope").HasMaxLength(2048);
            entity.Property(e => e.Resources).HasColumnName("resources").HasMaxLength(4096);
            entity.Property(e => e.CreatedAt).HasColumnName("created_at");
            entity.Property(e => e.AuthTime).HasColumnName("auth_time");
            entity.Property(e => e.RevokedAt).HasColumnName("revoked_at");

            // Bounded at the same number ApprovingDevice.MaxLength caps the header to, so the
            // column and the reader agree. A caller-controlled header with no limit of its own
            // reaching an unbounded column is a row somebody can make arbitrarily large.
            entity.Property(e => e.UserAgent).HasColumnName("user_agent").HasMaxLength(256);
        });

        modelBuilder.Entity<ConsentRow>(entity =>
        {
            entity.ToTable("consents");
            entity.HasKey(e => new { e.Subject, e.ClientId });
            entity.Property(e => e.Subject).HasColumnName("subject").HasMaxLength(64);
            entity.Property(e => e.ClientId).HasColumnName("client_id").HasMaxLength(512);
            entity.Property(e => e.ClientIdKind).HasColumnName("client_id_kind");
            entity.Property(e => e.Scope).HasColumnName("scope").HasMaxLength(2048);
            entity.Property(e => e.Resources).HasColumnName("resources").HasMaxLength(4096);
            entity.Property(e => e.GrantedAt).HasColumnName("granted_at");
        });

        modelBuilder.Entity<UserRow>(entity =>
        {
            entity.ToTable("users");
            entity.HasKey(e => e.Subject);
            entity.Property(e => e.Subject).HasColumnName("subject").HasMaxLength(64);
            entity.Property(e => e.Realm).HasColumnName("realm").HasMaxLength(64).HasDefaultValue("default");
            entity.Property(e => e.Username).HasColumnName("username").HasMaxLength(256);
            entity.Property(e => e.NormalizedUsername).HasColumnName("normalized_username").HasMaxLength(256);
            entity.Property(e => e.Email).HasColumnName("email").HasMaxLength(320);
            entity.Property(e => e.NormalizedEmail).HasColumnName("normalized_email").HasMaxLength(320);
            entity.Property(e => e.EmailVerified).HasColumnName("email_verified");
            entity.Property(e => e.PasswordHash).HasColumnName("password_hash").HasMaxLength(512);
            entity.Property(e => e.DisabledAt).HasColumnName("disabled_at");
            entity.Property(e => e.SessionsValidFrom).HasColumnName("sessions_valid_from");

            // Unique, so "two accounts differing only by case" is refused by the database and not
            // only by the check above it. The check still runs, because it produces the
            // InvalidOperationException the contract asks for rather than a provider exception.
            //
            // Composite with the realm, from the first migration that has realms at all. A realm
            // column that exists and is not in the index reads as tenancy and is not: two realms
            // would be unable to hold the same username, which is the one thing having realms is
            // for. Realm first, because a lookup always knows it.
            entity.HasIndex(e => new { e.Realm, e.NormalizedUsername })
                .IsUnique()
                .HasDatabaseName("ux_users_realm_normalized_username");

            // Not unique, unlike the username above, and the difference is stated on
            // UserRow.NormalizedEmail: no rule has ever made an address unique, so a unique index
            // would refuse to migrate a deployment that already holds a duplicate.
            //
            // It exists at all because FindByVerifiedEmailAsync is reached from the sign-in form.
            // Without it that lookup is a scan, which is unbounded work an anonymous caller asks
            // for by typing something with an @ in it.
            entity.HasIndex(e => new { e.Realm, e.NormalizedEmail })
                .HasDatabaseName("ix_users_realm_normalized_email");
        });

        modelBuilder.Entity<AdminAuditRow>(entity =>
        {
            entity.ToTable("admin_audit");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id").ValueGeneratedOnAdd();
            entity.Property(e => e.At).HasColumnName("at");
            entity.Property(e => e.ActorKind).HasColumnName("actor_kind").HasMaxLength(16);
            entity.Property(e => e.ActorSubject).HasColumnName("actor_subject").HasMaxLength(64);
            entity.Property(e => e.ActorClient).HasColumnName("actor_client").HasMaxLength(512);
            entity.Property(e => e.Action).HasColumnName("action").HasMaxLength(64);
            entity.Property(e => e.TargetRealm).HasColumnName("target_realm").HasMaxLength(64);
            entity.Property(e => e.TargetSubject).HasColumnName("target_subject").HasMaxLength(64);
            entity.Property(e => e.TargetHandle).HasColumnName("target_handle").HasMaxLength(256);
            entity.Property(e => e.Outcome).HasColumnName("outcome").HasMaxLength(16);
            entity.Property(e => e.Detail).HasColumnName("detail").HasMaxLength(256);
            entity.Property(e => e.CorrelationId).HasColumnName("correlation_id").HasMaxLength(64);

            // The two questions this table is read with: "what happened lately" and "what has been
            // done to this account". Neither is answerable by a scan once the table is a year old,
            // and an audit log is the one table nobody prunes.
            entity.HasIndex(e => e.At).HasDatabaseName("ix_admin_audit_at");
            entity.HasIndex(e => new { e.TargetSubject, e.At }).HasDatabaseName("ix_admin_audit_target_at");

            // No foreign key to users. An entry must outlive the account it describes — that is most
            // of the point of anonymisation keeping the subject row, and all of the point of
            // recording an action against a handle that resolved to nobody.
        });

        modelBuilder.Entity<ClientAssertionRow>(entity =>
        {
            entity.ToTable("client_assertions");

            // The composite key is the replay check. TryClaimAsync inserts and reports what the
            // insert did; there is no read to race with, because the unique violation is the answer.
            entity.HasKey(e => new { e.ClientId, e.JwtId });

            // A client_id here is a CIMD URL, which is why this is not the 64 a subject gets. The
            // jti is the client's own opaque string: capped so a client cannot write an unbounded
            // value into this server's storage on every authentication, and generously, because a
            // refusal for length would look to the client like a replay it did not make. The
            // validator rejects an over-long one before it reaches here, with its own message.
            entity.Property(e => e.ClientId).HasColumnName("client_id").HasMaxLength(512);
            entity.Property(e => e.JwtId).HasColumnName("jwt_id").HasMaxLength(256);
            entity.Property(e => e.ExpiresAt).HasColumnName("expires_at");

            // The sweeper's predicate, and the same reasoning the codes and links tables carry:
            // housekeeping that scans is housekeeping that gets turned off.
            entity.HasIndex(e => e.ExpiresAt).HasDatabaseName("ix_client_assertions_expires_at");

            // No foreign key to clients. A CIMD client is resolved per request and deliberately
            // never persisted — a hundred sequential connections leave that table empty — so a
            // reference to it would be a reference to a row that is not there.
        });

        modelBuilder.Entity<UserTokenRow>(entity =>
        {
            entity.ToTable("user_tokens");
            entity.HasKey(e => e.TokenHash);
            entity.Property(e => e.TokenHash).HasColumnName("token_hash").HasMaxLength(32);
            entity.Property(e => e.Subject).HasColumnName("subject").HasMaxLength(64);
            entity.Property(e => e.Purpose).HasColumnName("purpose");
            entity.Property(e => e.ExpiresAt).HasColumnName("expires_at");
            entity.Property(e => e.Detail).HasColumnName("detail").HasMaxLength(320);

            // S-47's bulk delete runs on every password change by any route, so it is on a request
            // path — unlike the grant sweep, which runs when an operator is signing somebody out.
            // Without this index it is a scan of every live link in the deployment each time
            // anybody changes a password.
            entity.HasIndex(e => new { e.Subject, e.Purpose }).HasDatabaseName("ix_user_tokens_subject_purpose");

            // The sweeper's predicate. Same reasoning as the codes table: housekeeping that scans
            // is housekeeping that gets turned off.
            entity.HasIndex(e => e.ExpiresAt).HasDatabaseName("ix_user_tokens_expires_at");

            // No foreign key to users, matching admin_audit and for a narrower reason: anonymising
            // an account must not fail because a reset link was outstanding. The link is destroyed
            // by the operation rather than by the database.
        });

        modelBuilder.Entity<ExternalLoginRow>(entity =>
        {
            entity.ToTable("external_logins");
            entity.HasKey(e => new { e.Realm, e.UpstreamIssuer, e.UpstreamSubject });
            entity.Property(e => e.Realm).HasColumnName("realm").HasMaxLength(64).HasDefaultValue("default");
            entity.Property(e => e.UpstreamIssuer).HasColumnName("upstream_issuer").HasMaxLength(512);
            entity.Property(e => e.UpstreamSubject).HasColumnName("upstream_subject").HasMaxLength(512);
            entity.Property(e => e.Subject).HasColumnName("subject").HasMaxLength(64);

            entity.HasIndex(e => e.Subject).HasDatabaseName("ix_external_logins_subject");

            // The foreign key the in-memory store enforces by hand, declared so a dangling link
            // cannot survive a store that skipped the check.
            //
            // Whether the database enforces it is a separate question from whether it is declared:
            // SQLite ignores REFERENCES clauses unless `PRAGMA foreign_keys` is on, and it is off by
            // default and set per connection. EF Core's SQLite provider turns it on when it opens
            // one — which is a property of a library this project does not own, so
            // SqliteSchemaTests.The_connection_enforces_foreign_keys reads the pragma back rather
            // than trusting this comment.
            entity.HasOne<UserRow>()
                .WithMany()
                .HasForeignKey(e => e.Subject)
                .HasPrincipalKey(u => u.Subject)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<RoleRow>(entity =>
        {
            entity.ToTable("roles");

            // Realm first, because every lookup knows it — the same ordering and the same reason as
            // the username index above.
            entity.HasKey(e => new { e.Realm, e.Id });
            entity.Property(e => e.Realm).HasColumnName("realm").HasMaxLength(64).HasDefaultValue("default");
            entity.Property(e => e.Id).HasColumnName("id").HasMaxLength(64);
            entity.Property(e => e.Name).HasColumnName("name").HasMaxLength(128);

            // Space-separated, and sized for it. 1024 holds sixteen sixty-character permissions,
            // which is well past any vocabulary a person can keep in their head — and a column that
            // could hold more would be a column somebody keeps a policy document in.
            entity.Property(e => e.Permissions).HasColumnName("permissions").HasMaxLength(1024);
        });

        modelBuilder.Entity<ClientRow>(entity =>
        {
            entity.ToTable("clients");

            entity.HasKey(e => e.ClientId);

            // 512, matching every other client_id column in this schema. A CIMD identifier is a URL
            // and these are not, but one width across the schema is what keeps a join from
            // truncating on the one table that chose a smaller number.
            entity.Property(e => e.ClientId).HasColumnName("client_id").HasMaxLength(512);
            entity.Property(e => e.ClientIdKind).HasColumnName("client_id_kind");
            entity.Property(e => e.Name).HasColumnName("name").HasMaxLength(256);

            // Fixed 32, not a blob. A SHA-256 is exactly that long, and a column that could hold
            // more is a column somebody eventually puts a plaintext secret in.
            entity.Property(e => e.SecretHash).HasColumnName("secret_hash").HasMaxLength(32);

            // 64, matching users.subject, because that is what it points at. No foreign key: the
            // owner may live in a directory this table's database does not hold — IUserStore is a
            // seam a deployment can implement against anything — so a constraint here would forbid
            // a shape the interfaces allow. The grant refuses an owner it cannot resolve, which is
            // the check that works whatever the directory is.
            entity.Property(e => e.Owner).HasColumnName("owner").HasMaxLength(64);

            entity.Property(e => e.Scopes).HasColumnName("scopes").HasMaxLength(1024);
            entity.Property(e => e.RedirectUris).HasColumnName("redirect_uris").HasMaxLength(2048);
            entity.Property(e => e.DisabledAt).HasColumnName("disabled_at");
            entity.Property(e => e.CreatedAt).HasColumnName("created_at");

            // "Which service accounts act as this person", which is the question asked when
            // somebody leaves and the one that has to be answerable before their account is
            // disabled.
            //
            // Unfiltered, though most rows will have a null owner. A partial index is written in
            // provider-specific SQL and this model is shared by SQLite and PostgreSQL, so the filter
            // would have to be right in two dialects to save an index scan on a table that holds
            // clients rather than tokens — tens of rows, not millions. The cost of being wrong is
            // larger than the thing being bought.
            entity.HasIndex(e => e.Owner).HasDatabaseName("ix_clients_owner");
        });

        modelBuilder.Entity<UserRoleRow>(entity =>
        {
            entity.ToTable("user_roles");

            entity.HasKey(e => new { e.Subject, e.RoleId });
            entity.Property(e => e.Subject).HasColumnName("subject").HasMaxLength(64);
            entity.Property(e => e.Realm).HasColumnName("realm").HasMaxLength(64).HasDefaultValue("default");
            entity.Property(e => e.RoleId).HasColumnName("role_id").HasMaxLength(64);

            // The navigation the account read uses, so one query answers "who is this and what do
            // they hold". Cascade, because an assignment outliving its account is a row nothing can
            // ever reach.
            entity.HasOne(e => e.User)
                .WithMany(u => u.Roles)
                .HasForeignKey(e => e.Subject)
                .HasPrincipalKey(u => u.Subject)
                .OnDelete(DeleteBehavior.Cascade);

            // And the other side: an assignment naming a role the realm does not define is refused
            // by the database, not only by the check above it. `IUserStore.SetRolesAsync` checks
            // first so the caller gets a message naming the id they mistyped; this is what holds if
            // that check is ever raced, and what makes deleting a role take its assignments with it
            // rather than leaving rows pointing at nothing.
            entity.HasOne<RoleRow>()
                .WithMany()
                .HasForeignKey(e => new { e.Realm, e.RoleId })
                .HasPrincipalKey(r => new { r.Realm, r.Id })
                .OnDelete(DeleteBehavior.Cascade);
        });
    }
}
