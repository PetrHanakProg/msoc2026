using System.Text.Json;
using Bit.Core.AdminConsole.Entities;
using Bit.Core.AdminConsole.Repositories;
using Bit.Core.Entities;
using Bit.Core.Enums;
using Bit.Core.Models.Data;
using Bit.Core.Repositories;
using Bit.Core.Utilities;
using Bit.Core.Vault.Entities;
using Bit.Core.Vault.Enums;
using Bit.Core.Vault.Repositories;

namespace Bit.Infrastructure.IntegrationTest.Vault.Repositories;

// Fixture JSON model mirrors the structure produced by instance_to_fixture.py

public class AlloyCipherFixture
{
    public string Name { get; set; } = "";
    public AlloyCipherFixtureExpected Expected { get; set; } = new();
    public AlloyCipherFixtureSubject TestSubject { get; set; } = new();
    public AlloyCipherFixtureEntities Entities { get; set; } = new();
}

public class AlloyCipherFixtureExpected
{
    public bool? CanSee { get; set; }
    public bool? CanEdit { get; set; }
    public bool? CanViewPassword { get; set; }
    public bool? CanManage { get; set; }
}

public class AlloyCipherFixtureSubject
{
    public string User { get; set; } = "";
    public string Cipher { get; set; } = "";
}

public class AlloyCipherFixtureEntities
{
    public List<FixtureUser> Users { get; set; } = [];
    public List<FixtureOrganization> Organizations { get; set; } = [];
    public List<FixtureCipher> Ciphers { get; set; } = [];
    public List<FixtureCollection> Collections { get; set; } = [];
    public List<FixtureCollectionCipher> CollectionCiphers { get; set; } = [];
    public List<FixtureOrganizationUser> OrganizationUsers { get; set; } = [];
    public List<FixtureGroup> Groups { get; set; } = [];
    public List<FixtureGroupUser> GroupUsers { get; set; } = [];
    public List<FixtureCollectionUser> CollectionUsers { get; set; } = [];
    public List<FixtureCollectionGroup> CollectionGroups { get; set; } = [];
}

public class FixtureUser
{
    public string AlloyId { get; set; } = "";
}

public class FixtureOrganization
{
    public string AlloyId { get; set; } = "";
    public bool Enabled { get; set; }
    public bool AllowAdminAccess { get; set; }
}

public class FixtureCipher
{
    public string AlloyId { get; set; } = "";
    public string? OwnerOrg { get; set; }
    public string? OwnerUser { get; set; }
}

public class FixtureCollection
{
    public string AlloyId { get; set; } = "";
    public string OrgId { get; set; } = "";
}

public class FixtureCollectionCipher
{
    public string CollectionId { get; set; } = "";
    public string CipherId { get; set; } = "";
}

public class FixtureOrganizationUser
{
    public string AlloyId { get; set; } = "";
    public string? UserId { get; set; }
    public string OrgId { get; set; } = "";
    public int Status { get; set; }
    public int Type { get; set; }
    public bool HasKey { get; set; }
}

public class FixtureGroup
{
    public string AlloyId { get; set; } = "";
    public string OrgId { get; set; } = "";
}

public class FixtureGroupUser
{
    public string GroupId { get; set; } = "";
    public string OrgUserId { get; set; } = "";
}

public class FixtureCollectionUser
{
    public string CollectionId { get; set; } = "";
    public string OrgUserId { get; set; } = "";
    public bool ReadOnly { get; set; }
    public bool HidePasswords { get; set; }
    public bool Manage { get; set; }
}

public class FixtureCollectionGroup
{
    public string CollectionId { get; set; } = "";
    public string GroupId { get; set; } = "";
    public bool ReadOnly { get; set; }
    public bool HidePasswords { get; set; }
    public bool Manage { get; set; }
}


// Helper methods

public static class AlloyCipherFixtureHelpers
{
    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    // Load a fixture by name from the embedded AlloyCipherFixtureData dictionary.
    // Throws KeyNotFoundException if the name is not found.
    public static AlloyCipherFixture LoadFixture(string name)
    {
        if (!AlloyCipherFixtureData.Fixtures.TryGetValue(name, out var json))
        {
            throw new KeyNotFoundException(
                $"No fixture named '{name}'. Available: {string.Join(", ", AlloyCipherFixtureData.Fixtures.Keys)}"
            );
        }
        return JsonSerializer.Deserialize<AlloyCipherFixture>(json, _jsonOptions)
               ?? throw new InvalidOperationException($"Failed to deserialize fixture '{name}'");
    }

    // Create all entities described by the fixture in FK-dependency order and return
    // the (userId, cipherId) pair identifying the test subject.
    public static async Task<(Guid userId, Guid cipherId)> CreateEntitiesFromFixture(
        AlloyCipherFixture fixture,
        IUserRepository userRepository,
        IOrganizationRepository organizationRepository,
        IOrganizationUserRepository organizationUserRepository,
        ICollectionRepository collectionRepository,
        ICollectionCipherRepository collectionCipherRepository,
        IGroupRepository groupRepository,
        ICipherRepository cipherRepository)
    {
        var idMap = new Dictionary<string, Guid>();

        var runTag = Guid.NewGuid().ToString("N")[..8];

        // 1. Users
        foreach (var fu in fixture.Entities.Users)
        {
            var user = await userRepository.CreateAsync(new User
            {
                Name          = $"alloy-{fu.AlloyId}",
                Email         = $"{fu.AlloyId}-{runTag}@alloy.test",
                ApiKey        = "TEST",
                SecurityStamp = "stamp",
            });
            idMap[fu.AlloyId] = user.Id;
        }

        // 2. Organizations
        foreach (var fo in fixture.Entities.Organizations)
        {
            var org = await organizationRepository.CreateAsync(new Organization
            {
                Name                                = $"alloy-org-{fo.AlloyId}-{runTag}",
                BillingEmail                        = $"billing-{fo.AlloyId}-{runTag}@alloy.test",
                Plan                                = "Enterprise (Annually)",
                PlanType                            = Bit.Core.Billing.Enums.PlanType.EnterpriseAnnually,
                Enabled                             = fo.Enabled,
                AllowAdminAccessToAllCollectionItems = fo.AllowAdminAccess,
                UseGroups                           = true,
                UseCustomPermissions                = true,
                LicenseKey                          = $"license-{fo.AlloyId}",
                PublicKey                           = "test-public-key",
                PrivateKey                          = "test-private-key",
                ExpirationDate                      = DateTime.UtcNow.AddYears(1),
                Status                              = OrganizationStatusType.Managed,
            });
            idMap[fo.AlloyId] = org.Id;
        }

        // 3. Ciphers
        foreach (var fc in fixture.Entities.Ciphers)
        {
            var ownerUserId = fc.OwnerUser != null ? idMap[fc.OwnerUser] : (Guid?)null;
            var ownerOrgId  = fc.OwnerOrg  != null ? idMap[fc.OwnerOrg]  : (Guid?)null;
            var cipher = await cipherRepository.CreateAsync(new Cipher
            {
                Type           = CipherType.Login,
                UserId         = ownerUserId,
                OrganizationId = ownerOrgId,
                Data           = "{}",
            });
            idMap[fc.AlloyId] = cipher.Id;
        }

        // 4. Collections
        foreach (var fcol in fixture.Entities.Collections)
        {
            var orgId = idMap[fcol.OrgId];
            var col = await collectionRepository.CreateAsync(new Collection
            {
                OrganizationId = orgId,
                Name           = $"alloy-col-{fcol.AlloyId}",
            });
            idMap[fcol.AlloyId] = col.Id;
        }

        // 5. OrganizationUsers
        foreach (var fou in fixture.Entities.OrganizationUsers)
        {
            var orgId  = idMap[fou.OrgId];
            var userId = fou.UserId != null ? idMap[fou.UserId] : (Guid?)null;
            var ou = await organizationUserRepository.CreateAsync(new OrganizationUser
            {
                OrganizationId = orgId,
                UserId         = userId,
                Status         = (OrganizationUserStatusType)fou.Status,
                Type           = (OrganizationUserType)fou.Type,
                Key            = fou.HasKey ? "test-key-sentinel" : null,
            });
            idMap[fou.AlloyId] = ou.Id;
        }

        // 6. Groups - CreateAsync returns Task (void) but mutates obj.Id via base.CreateAsync.
        foreach (var fg in fixture.Entities.Groups)
        {
            var orgId = idMap[fg.OrgId];
            var group = new Group { OrganizationId = orgId, Name = $"alloy-group-{fg.AlloyId}" };
            await groupRepository.CreateAsync(group, collections: []);
            idMap[fg.AlloyId] = group.Id;
        }

        // 7. GroupUsers (Group.members junction)
        // Batch by groupId - UpdateUsersAsync replaces all members for that group.
        var groupUserMap = new Dictionary<Guid, List<Guid>>();
        foreach (var fgu in fixture.Entities.GroupUsers)
        {
            var groupId   = idMap[fgu.GroupId];
            var orgUserId = idMap[fgu.OrgUserId];
            if (!groupUserMap.ContainsKey(groupId)) groupUserMap[groupId] = [];
            groupUserMap[groupId].Add(orgUserId);
        }
        foreach (var (groupId, ouIds) in groupUserMap)
        {
            await groupRepository.UpdateUsersAsync(groupId, ouIds, DateTime.UtcNow);
        }

        // 8. CollectionCiphers (Collection.ciphers junction)
        // UpdateCollectionsForAdminAsync(cipherId, orgId, [collectionIds]) - called per cipher.
        var cipherCollectionsMap = new Dictionary<Guid, (Guid orgId, List<Guid> colIds)>();
        foreach (var fcc in fixture.Entities.CollectionCiphers)
        {
            var colId    = idMap[fcc.CollectionId];
            var cipherId = idMap[fcc.CipherId];
            // Find the org for this collection from the fixture
            var fcol  = fixture.Entities.Collections.First(c => c.AlloyId == fcc.CollectionId);
            var orgId = idMap[fcol.OrgId];
            if (!cipherCollectionsMap.ContainsKey(cipherId))
                cipherCollectionsMap[cipherId] = (orgId, []);
            cipherCollectionsMap[cipherId].colIds.Add(colId);
        }
        foreach (var (cipherId, (orgId, colIds)) in cipherCollectionsMap)
        {
            await collectionCipherRepository.UpdateCollectionsForAdminAsync(cipherId, orgId, colIds);
        }

        // 9. CollectionUsers
        // UpdateUsersAsync(collectionId, IEnumerable<CollectionAccessSelection>) - called per collection.
        var collectionUsersMap = new Dictionary<Guid, List<CollectionAccessSelection>>();
        foreach (var fcu in fixture.Entities.CollectionUsers)
        {
            var colId = idMap[fcu.CollectionId];
            var ouId  = idMap[fcu.OrgUserId];
            if (!collectionUsersMap.ContainsKey(colId)) collectionUsersMap[colId] = [];
            collectionUsersMap[colId].Add(new CollectionAccessSelection
            {
                Id            = ouId,
                ReadOnly      = fcu.ReadOnly,
                HidePasswords = fcu.HidePasswords,
                Manage        = fcu.Manage,
            });
        }
        foreach (var (colId, selections) in collectionUsersMap)
        {
            await collectionRepository.UpdateUsersAsync(colId, selections);
        }

        // 10. CollectionGroups
        // ReplaceAsync(Group, IEnumerable<CollectionAccessSelection>) - replaces all collection
        // access for that group. Called once per group after all collection grants are known.
        var collectionGroupsMap = new Dictionary<Guid, List<CollectionAccessSelection>>();
        foreach (var fcg in fixture.Entities.CollectionGroups)
        {
            var groupId = idMap[fcg.GroupId];
            var colId   = idMap[fcg.CollectionId];
            if (!collectionGroupsMap.ContainsKey(groupId)) collectionGroupsMap[groupId] = [];
            collectionGroupsMap[groupId].Add(new CollectionAccessSelection
            {
                Id            = colId,
                ReadOnly      = fcg.ReadOnly,
                HidePasswords = fcg.HidePasswords,
                Manage        = fcg.Manage,
            });
        }
        foreach (var (groupId, selections) in collectionGroupsMap)
        {
            var fg    = fixture.Entities.Groups.First(g => idMap[g.AlloyId] == groupId);
            var orgId = idMap[fg.OrgId];
            await groupRepository.ReplaceAsync(
                new Group { Id = groupId, OrganizationId = orgId, Name = $"alloy-group-{groupId}" },
                selections
            );
        }

        return (idMap[fixture.TestSubject.User], idMap[fixture.TestSubject.Cipher]);
    }
}
