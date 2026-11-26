
from app import saas_store, firestore_store


def main():
    email = input("Enter an existing organization owner's email: ").strip()
    organization_id = input("Enter that organization's ID: ").strip()

    print("\nChecking organization access...")

    organization = saas_store.get_org(email, organization_id)

    if not organization:
        print("ERROR: Organization not found or access denied.")
        return

    print("Organization access verified.")
    print("Organization name:", organization["name"])

    confirmation = input(
        "\nType SYNC to copy this profile to Firestore: "
    ).strip()

    if confirmation != "SYNC":
        print("Synchronization cancelled.")
        return

    result = firestore_store.sync_organization_profile(
        email,
        organization_id,
    )

    print("\nSynchronization completed.")
    print("Organization ID:", result["organization_id"])
    print("Organization name:", result["name"])
    print("Organization slug:", result["slug"])

    print("\nVerifying Firestore read...")

    saved = firestore_store.get_organization_profile(organization_id)

    if saved and saved["organization_id"] == organization_id:
        print("SUCCESS: Firestore profile verified.")
    else:
        print("ERROR: Firestore verification failed.")


if __name__ == "__main__":
    main()
