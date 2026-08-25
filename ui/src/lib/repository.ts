export const SHAKERSCAN_REPOSITORY_URL = 'https://github.com/andriyze/shakerscan'

// Installed V2 builds must not send operators to documentation from the
// independently moving main branch. Release tooling can keep this stable
// until the V2 documentation is promoted with the release.
export const SHAKERSCAN_DOCUMENTATION_BLOB_URL = `${SHAKERSCAN_REPOSITORY_URL}/blob/v2`
