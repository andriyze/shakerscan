import { getApiErrorMessage } from './apiConfig'
import { ApiError } from './fetchLayer.mjs'

/** A failed response as an error that keeps its HTTP status, so a page can tell 404 from a failure. */
export async function apiFailure(response: Response, fallback: string): Promise<ApiError> {
  return new ApiError(await getApiErrorMessage(response, fallback), { status: response.status })
}
