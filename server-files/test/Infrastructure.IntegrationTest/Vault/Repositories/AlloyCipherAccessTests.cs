using Bit.Core.AdminConsole.Entities;
using Bit.Core.AdminConsole.Repositories;
using Bit.Core.Entities;
using Bit.Core.Enums;
using Bit.Core.Models.Data;
using Bit.Core.Repositories;
using Bit.Core.Vault.Entities;
using Bit.Core.Vault.Enums;
using Bit.Core.Vault.Repositories;
using Xunit;

namespace Bit.Infrastructure.IntegrationTest.Repositories;

public class AlloyCipherAccessTests
{
    // PERSONAL CIPHER TESTS

    [DatabaseTheory, DatabaseData]
    public async Task PersonalCipher_OwnerCanSee_Edit_Manage(
        IUserRepository userRepository,
        ICipherRepository cipherRepository)
    {
        var user = await userRepository.CreateAsync(new User
        {
            Name = "Test User",
            Email = $"test+{Guid.NewGuid()}@email.com",
            ApiKey = "TEST",
            SecurityStamp = "stamp",
        });

        var cipher = await cipherRepository.CreateAsync(new Cipher
        {
            Type = CipherType.Login,
            UserId = user.Id,
            Data = "",
        });

        var results = await cipherRepository.GetManyByUserIdAsync(user.Id);

        var details = Assert.Single(results, c => c.Id == cipher.Id);
        Assert.True(details.Edit);
        Assert.True(details.ViewPassword);
        Assert.True(details.Manage);
    }

    [DatabaseTheory, DatabaseData]
    public async Task PersonalCipher_OtherUserCannotSee(
        IUserRepository userRepository,
        ICipherRepository cipherRepository)
    {
        var userA = await userRepository.CreateAsync(new User
        {
            Name = "User A",
            Email = $"test+{Guid.NewGuid()}@email.com",
            ApiKey = "TEST",
            SecurityStamp = "stamp",
        });

        var userB = await userRepository.CreateAsync(new User
        {
            Name = "User B",
            Email = $"test+{Guid.NewGuid()}@email.com",
            ApiKey = "TEST",
            SecurityStamp = "stamp",
        });

        await cipherRepository.CreateAsync(new Cipher
        {
            Type = CipherType.Login,
            UserId = userA.Id,
            Data = "",
        });

        var userBResults = await cipherRepository.GetManyByUserIdAsync(userB.Id);

        Assert.DoesNotContain(userBResults, c => c.UserId == userA.Id);
    }

    // ORG CIPHER  DIRECT COLLECTION GRANT TESTS

    [DatabaseTheory, DatabaseData]
    public async Task OrgCipher_DirectReadOnlyGrant_CanSeeNotEdit(
        IUserRepository userRepository,
        IOrganizationRepository organizationRepository,
        IOrganizationUserRepository organizationUserRepository,
        ICollectionRepository collectionRepository,
        ICollectionCipherRepository collectionCipherRepository,
        ICipherRepository cipherRepository)
    {
        var (user, org, orgUser) = await CreateUserOrgAndMember(
            userRepository, organizationRepository, organizationUserRepository,
            OrganizationUserType.User);

        var (cipher, _) = await CreateOrgCipherInCollectionWithDirectGrant(
            org, orgUser, cipherRepository, collectionRepository, collectionCipherRepository,
            readOnly: true, hidePasswords: false, manage: false);

        var results = await cipherRepository.GetManyByUserIdAsync(user.Id);

        var details = Assert.Single(results, c => c.Id == cipher.Id);
        Assert.False(details.Edit);
        Assert.True(details.ViewPassword);
        Assert.False(details.Manage);
    }

    [DatabaseTheory, DatabaseData]
    public async Task OrgCipher_DirectHidePasswordsGrant_CanSeeNotViewPassword(
        IUserRepository userRepository,
        IOrganizationRepository organizationRepository,
        IOrganizationUserRepository organizationUserRepository,
        ICollectionRepository collectionRepository,
        ICollectionCipherRepository collectionCipherRepository,
        ICipherRepository cipherRepository)
    {
        var (user, org, orgUser) = await CreateUserOrgAndMember(
            userRepository, organizationRepository, organizationUserRepository,
            OrganizationUserType.User);

        var (cipher, _) = await CreateOrgCipherInCollectionWithDirectGrant(
            org, orgUser, cipherRepository, collectionRepository, collectionCipherRepository,
            readOnly: false, hidePasswords: true, manage: false);

        var results = await cipherRepository.GetManyByUserIdAsync(user.Id);

        var details = Assert.Single(results, c => c.Id == cipher.Id);
        Assert.True(details.Edit);
        Assert.False(details.ViewPassword);
        Assert.False(details.Manage);
    }

    [DatabaseTheory, DatabaseData]
    public async Task OrgCipher_DirectManageGrant_CanManage(
        IUserRepository userRepository,
        IOrganizationRepository organizationRepository,
        IOrganizationUserRepository organizationUserRepository,
        ICollectionRepository collectionRepository,
        ICollectionCipherRepository collectionCipherRepository,
        ICipherRepository cipherRepository)
    {
        var (user, org, orgUser) = await CreateUserOrgAndMember(
            userRepository, organizationRepository, organizationUserRepository,
            OrganizationUserType.User);

        var (cipher, _) = await CreateOrgCipherInCollectionWithDirectGrant(
            org, orgUser, cipherRepository, collectionRepository, collectionCipherRepository,
            readOnly: false, hidePasswords: false, manage: true);

        var results = await cipherRepository.GetManyByUserIdAsync(user.Id);

        var details = Assert.Single(results, c => c.Id == cipher.Id);
        Assert.True(details.Edit);
        Assert.True(details.ViewPassword);
        Assert.True(details.Manage);
    }

    // ORG CIPHER MEMBERSHIP LIFECYCLE TESTS

    [DatabaseTheory, DatabaseData]
    public async Task OrgCipher_RevokedMember_NotVisible(
        IUserRepository userRepository,
        IOrganizationRepository organizationRepository,
        IOrganizationUserRepository organizationUserRepository,
        ICollectionRepository collectionRepository,
        ICollectionCipherRepository collectionCipherRepository,
        ICipherRepository cipherRepository)
    {
        var (user, org, orgUser) = await CreateUserOrgAndMember(
            userRepository, organizationRepository, organizationUserRepository,
            OrganizationUserType.User, status: OrganizationUserStatusType.Revoked);

        var (cipher, _) = await CreateOrgCipherInCollectionWithDirectGrant(
            org, orgUser, cipherRepository, collectionRepository, collectionCipherRepository,
            readOnly: false, hidePasswords: false, manage: false);

        var results = await cipherRepository.GetManyByUserIdAsync(user.Id);

        Assert.DoesNotContain(results, c => c.Id == cipher.Id);
    }

    [DatabaseTheory, DatabaseData]
    public async Task OrgCipher_DisabledOrg_NotVisible(
        IUserRepository userRepository,
        IOrganizationRepository organizationRepository,
        IOrganizationUserRepository organizationUserRepository,
        ICollectionRepository collectionRepository,
        ICollectionCipherRepository collectionCipherRepository,
        ICipherRepository cipherRepository)
    {
        var (user, org, orgUser) = await CreateUserOrgAndMember(
            userRepository, organizationRepository, organizationUserRepository,
            OrganizationUserType.User);

        var (cipher, _) = await CreateOrgCipherInCollectionWithDirectGrant(
            org, orgUser, cipherRepository, collectionRepository, collectionCipherRepository,
            readOnly: false, hidePasswords: false, manage: false);

        org.Enabled = false;
        await organizationRepository.ReplaceAsync(org);

        var results = await cipherRepository.GetManyByUserIdAsync(user.Id);

        Assert.DoesNotContain(results, c => c.Id == cipher.Id);
    }

    [DatabaseTheory, DatabaseData]
    public async Task OrgCipher_NotInAnyCollection_MemberCannotSee(
        IUserRepository userRepository,
        IOrganizationRepository organizationRepository,
        IOrganizationUserRepository organizationUserRepository,
        ICipherRepository cipherRepository)
    {
        var (user, org, _) = await CreateUserOrgAndMember(
            userRepository, organizationRepository, organizationUserRepository,
            OrganizationUserType.User);

        // Cipher exists in the org but is intentionally not assigned to any collection.
        var cipher = await cipherRepository.CreateAsync(new Cipher
        {
            Type = CipherType.Login,
            OrganizationId = org.Id,
            Data = "",
        });

        var results = await cipherRepository.GetManyByUserIdAsync(user.Id);

        Assert.DoesNotContain(results, c => c.Id == cipher.Id);
    }

    // ORG CIPHER  GROUP GRANT TESTS

    [DatabaseTheory, DatabaseData]
    public async Task OrgCipher_GroupGrantOnly_CanSeeWithGroupPermissions(
        IUserRepository userRepository,
        IOrganizationRepository organizationRepository,
        IOrganizationUserRepository organizationUserRepository,
        IGroupRepository groupRepository,
        ICollectionRepository collectionRepository,
        ICollectionCipherRepository collectionCipherRepository,
        ICipherRepository cipherRepository)
    {
        var (user, org, orgUser) = await CreateUserOrgAndMember(
            userRepository, organizationRepository, organizationUserRepository,
            OrganizationUserType.User);

        var group = await groupRepository.CreateAsync(new Group
        {
            OrganizationId = org.Id,
            Name = "Test Group",
        });
        await groupRepository.UpdateUsersAsync(group.Id, new[] { orgUser.Id }, DateTime.UtcNow);

        var collection = await collectionRepository.CreateAsync(new Collection
        {
            Name = "Test Collection",
            OrganizationId = org.Id,
        });

        var cipher = await cipherRepository.CreateAsync(new Cipher
        {
            Type = CipherType.Login,
            OrganizationId = org.Id,
            Data = "",
        });

        await collectionCipherRepository.UpdateCollectionsForAdminAsync(
            cipher.Id, org.Id, new List<Guid> { collection.Id });

        // Group grant only, no direct CollectionUser row for this (orgUser, collection) pair.
        await groupRepository.ReplaceAsync(group, new[]
        {
            new CollectionAccessSelection
            {
                Id = collection.Id,
                ReadOnly = false,
                HidePasswords = false,
                Manage = false,
            },
        });

        var results = await cipherRepository.GetManyByUserIdAsync(user.Id);

        var details = Assert.Single(results, c => c.Id == cipher.Id);
        Assert.True(details.Edit);
        Assert.True(details.ViewPassword);
    }

    [DatabaseTheory, DatabaseData]
    public async Task OrgCipher_DirectReadOnlyGrantPrecedesGroupWriteGrant(
        IUserRepository userRepository,
        IOrganizationRepository organizationRepository,
        IOrganizationUserRepository organizationUserRepository,
        IGroupRepository groupRepository,
        ICollectionRepository collectionRepository,
        ICollectionCipherRepository collectionCipherRepository,
        ICipherRepository cipherRepository)
    {
        var (user, org, orgUser) = await CreateUserOrgAndMember(
            userRepository, organizationRepository, organizationUserRepository,
            OrganizationUserType.User);

        var group = await groupRepository.CreateAsync(new Group
        {
            OrganizationId = org.Id,
            Name = "Test Group",
        });
        await groupRepository.UpdateUsersAsync(group.Id, new[] { orgUser.Id }, DateTime.UtcNow);

        var (cipher, collection) = await CreateOrgCipherInCollectionWithDirectGrant(
            org, orgUser, cipherRepository, collectionRepository, collectionCipherRepository,
            readOnly: true, hidePasswords: false, manage: false);

        // Group grant on the same collection is more permissive (ReadOnly=false),
        // but the TVF's null-guard means it is silently ignored.
        await groupRepository.ReplaceAsync(group, new[]
        {
            new CollectionAccessSelection
            {
                Id = collection.Id,
                ReadOnly = false,
                HidePasswords = false,
                Manage = false,
            },
        });

        var results = await cipherRepository.GetManyByUserIdAsync(user.Id);

        var details = Assert.Single(results, c => c.Id == cipher.Id);
        Assert.False(details.Edit, "Direct ReadOnly=true grant must take precedence over group ReadOnly=false grant");
    }

    // PRIVATE HELPERS

    private static async Task<(User user, Organization org, OrganizationUser orgUser)> CreateUserOrgAndMember(
        IUserRepository userRepository,
        IOrganizationRepository organizationRepository,
        IOrganizationUserRepository organizationUserRepository,
        OrganizationUserType type,
        OrganizationUserStatusType status = OrganizationUserStatusType.Confirmed)
    {
        var user = await userRepository.CreateAsync(new User
        {
            Name = "Test User",
            Email = $"test+{Guid.NewGuid()}@email.com",
            ApiKey = "TEST",
            SecurityStamp = "stamp",
        });

        var org = await organizationRepository.CreateAsync(new Organization
        {
            Name = "Test Organization",
            BillingEmail = user.Email,
            Plan = "Test",
        });

        var orgUser = await organizationUserRepository.CreateAsync(new OrganizationUser
        {
            UserId = user.Id,
            OrganizationId = org.Id,
            Status = status,
            Type = type,
        });

        return (user, org, orgUser);
    }

    private static async Task<(Cipher cipher, Collection collection)> CreateOrgCipherInCollectionWithDirectGrant(
        Organization org,
        OrganizationUser orgUser,
        ICipherRepository cipherRepository,
        ICollectionRepository collectionRepository,
        ICollectionCipherRepository collectionCipherRepository,
        bool readOnly,
        bool hidePasswords,
        bool manage)
    {
        var collection = await collectionRepository.CreateAsync(new Collection
        {
            Name = $"Test Collection {Guid.NewGuid()}",
            OrganizationId = org.Id,
        });

        var cipher = await cipherRepository.CreateAsync(new Cipher
        {
            Type = CipherType.Login,
            OrganizationId = org.Id,
            Data = "",
        });

        await collectionCipherRepository.UpdateCollectionsForAdminAsync(
            cipher.Id, org.Id, new List<Guid> { collection.Id });

        await collectionRepository.UpdateUsersAsync(collection.Id, new List<CollectionAccessSelection>
        {
            new()
            {
                Id = orgUser.Id,
                ReadOnly = readOnly,
                HidePasswords = hidePasswords,
                Manage = manage,
            },
        });

        return (cipher, collection);
    }
}
