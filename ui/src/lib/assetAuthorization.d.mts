export interface AssetAuthorizationStatus {
  state: 'authorized' | 'partial' | 'web_apps' | 'none'
  label: string
  title: string
}

export declare function assetAuthorizationStatus(asset: {
  authorized?: boolean
  authorized_origin_count?: number
  origin_count?: number
  origins?: Array<{ is_active?: boolean; authorized?: boolean }>
} | null | undefined): AssetAuthorizationStatus
