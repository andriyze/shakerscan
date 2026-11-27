import { redirect } from 'next/navigation'

// Compatibility URL for bookmarks from the former Operator/Explorer split.
export default function LegacyOperatorRedirect() {
  redirect('/deep-hunt')
}
