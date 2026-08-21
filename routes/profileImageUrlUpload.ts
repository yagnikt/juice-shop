/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import dns from 'node:dns/promises'
import { URL } from 'node:url'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateOrReservedAddress (ip: string): boolean {
  if (ip.includes('.')) {
    const parts = ip.split('.').map(Number)
    if (parts.length !== 4 || parts.some(isNaN)) {
      return true
    }
    const [o1, o2, o3, o4] = parts
    if (o1 === 127) return true
    if (o1 === 10) return true
    if (o1 === 172 && o2 >= 16 && o2 <= 31) return true
    if (o1 === 192 && o2 === 168) return true
    if (o1 === 169 && o2 === 254) return true
    if (o1 === 0) return true
    if (o1 >= 224) return true
    return false
  }

  if (ip.includes(':')) {
    const normalized = ip.toLowerCase().replace(/[\[\]]/g, '')
    if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') return true
    if (normalized === '::' || normalized === '0:0:0:0:0:0:0:0') return true
    if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) return true
    if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true
    if (normalized.startsWith('ff')) return true
    if (normalized.startsWith('::ffff:')) {
      const ipv4Part = normalized.substring(7)
      if (ipv4Part.includes('.')) {
        return isPrivateOrReservedAddress(ipv4Part)
      }
    }
    return false
  }
  return true
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          let currentUrl = url
          let response: any = null
          let redirectCount = 0
          const maxRedirects = 5

          while (redirectCount <= maxRedirects) {
            let parsedUrl: URL
            try {
              parsedUrl = new URL(currentUrl)
            } catch (e) {
              throw new Error('Invalid URL format')
            }

            if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
              throw new Error('Only HTTP and HTTPS protocols are allowed')
            }

            const hostname = parsedUrl.hostname.replace(/[\[\]]/g, '')
            const addresses = await dns.lookup(hostname, { all: true })
            const isUnsafe = addresses.some(addr => isPrivateOrReservedAddress(addr.address))

            if (isUnsafe) {
              throw new Error('Access to private or reserved IP addresses is not allowed')
            }

            response = await fetch(currentUrl, { redirect: 'manual' })

            if ([301, 302, 303, 307, 308].includes(response.status)) {
              const location = response.headers.get('location')
              if (!location) {
                break
              }
              currentUrl = new URL(location, currentUrl).toString()
              redirectCount++
            } else {
              break
            }
          }

          if (!response || !response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
