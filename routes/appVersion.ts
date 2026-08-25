/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

import * as utils from '../lib/utils'

export function retrieveAppVersion () {
  // Returns current application version for client display
  return (_req: Request, res: Response) => {
    const appVersion = config.get('application.showVersionNumber') ? utils.version() : ''
    res.json({
      version: appVersion
    })
  }
}
