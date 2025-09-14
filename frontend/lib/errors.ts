export type ApiLikeError = Error & { code?: string; details?: any; request_id?: string; status?: number }

export function mapApiErrorToMessage(err: ApiLikeError): { title: string; description: string } {
  const code = (err as any)?.code as string | undefined
  const details = (err as any)?.details || {}
  const reqId = (err as any)?.request_id || details?.request_id
  let message = err.message || 'Request failed'

  switch (code) {
    case 'VALIDATION_ERROR': {
      // Try to extract field-specific details
      if (details?.field) {
        message = `Invalid ${details.field}`
      } else if (details?.fields) {
        const keys = Object.keys(details.fields)
        if (keys.length > 0) message = `Invalid ${keys[0]}`
      } else {
        message = 'Validation error'
      }
      break
    }
    case 'INVALID_FILE_TYPE':
      message = 'Unsupported file type. Please select a valid type'
      break
    case 'INVALID_FILE_FORMAT':
      if (details?.expected_ext && details?.got) {
        message = `File format mismatch (expected ${details.expected_ext}, got ${details.got})`
      } else {
        message = 'Unsupported file format'
      }
      break
    case 'PAYLOAD_TOO_LARGE':
      if (typeof details?.max_bytes === 'number') {
        const mb = Math.round((details.max_bytes / (1024*1024)) * 10) / 10
        message = `File is too large. Max ${mb} MB`
      } else {
        message = 'File is too large'
      }
      break
    case 'FILE_NOT_FOUND':
      message = 'File not found'
      break
    case 'USER_NOT_FOUND':
      message = 'User not found'
      break
    case 'API_KEY_NOT_FOUND':
      message = 'API key not found'
      break
    case 'INVALID_PERMISSION':
      message = 'Invalid or insufficient permissions'
      break
    case 'INVALID_STATUS':
      message = 'Invalid status value'
      break
    case 'INTERNAL_ERROR':
      message = 'Server error. Please try again later'
      break
    default:
      // keep original
      break
  }

  const suffix = reqId ? ` (ref: ${reqId})` : ''
  return { title: code || 'Error', description: `${message}${suffix}` }
}

