/**
 * One path segment of an API URL, built from a value the page did not choose itself (an ID from
 * the address bar, a link, a stored record). encodeURIComponent keeps a value inside its segment
 * ("a/b" cannot add a segment, "x?y" cannot start a query), but it leaves "." and ".." as they
 * are, and the URL parser resolves those (and their %2e spellings) as dot segments: an ID of
 * ".." would send a credentialed request to a different API route. Such a value is refused.
 */
export function pathSegment(value) {
  const text = String(value)
  if (text === '' || text === '.' || text === '..') {
    throw new Error('Refusing an empty or dot path segment in an API URL')
  }
  return encodeURIComponent(text)
}

/**
 * The query string of an API URL: "" for no parameters, otherwise "?" and the parameters as
 * URLSearchParams encodes them. Only URLSearchParams is taken, so a query is never hand-built from
 * raw values ("?target=" + target) that could add parameters or path text.
 */
export function queryString(params) {
  if (!(params instanceof URLSearchParams)) {
    throw new Error('An API query string must be built with URLSearchParams')
  }
  const text = params.toString()
  return text ? `?${text}` : ''
}
