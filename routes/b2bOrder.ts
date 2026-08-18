/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import vm from 'node:vm'
import { type Request, type Response, type NextFunction } from 'express'
// @ts-expect-error FIXME due to non-existing type definitions for notevil
import { eval as safeEval } from 'notevil'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

function isSafeInput (input: string): boolean {
  let unescaped = input.replace(/\\u\{([0-9a-fA-F]+)\}/g, (match, grp) => {
    try {
      return String.fromCodePoint(parseInt(grp, 16))
    } catch {
      return match
    }
  })
  unescaped = unescaped.replace(/\\u([0-9a-fA-F]{4})/g, (match, grp) => {
    try {
      return String.fromCharCode(parseInt(grp, 16))
    } catch {
      return match
    }
  })
  unescaped = unescaped.replace(/\\x([0-9a-fA-F]{2})/g, (match, grp) => {
    try {
      return String.fromCharCode(parseInt(grp, 16))
    } catch {
      return match
    }
  })

  const forbiddenPatterns = [
    /Function/,
    /eval/i,
    /constructor/i,
    /process/i,
    /require/i,
    /child_process/i,
    /mainModule/i,
    /exec/i,
    /spawn/i,
    /global/i,
    /prototype/i,
    /__proto__/i
  ]

  for (const pattern of forbiddenPatterns) {
    if (pattern.test(unescaped)) {
      return false
    }
  }

  return true
}

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    if (utils.isChallengeEnabled(challenges.rceChallenge) || utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
      const orderLinesData = body.orderLinesData || ''
      try {
        if (!isSafeInput(orderLinesData)) {
          throw new Error('Blocked: Potential sandbox escape or code injection detected!')
        }
        const sandbox = { safeEval, orderLinesData }
        vm.createContext(sandbox)
        vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
        res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
      } catch (err) {
        if (utils.getErrorMessage(err).match(/Script execution timed out.*/) != null) {
          challengeUtils.solveIf(challenges.rceOccupyChallenge, () => { return true })
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          challengeUtils.solveIf(challenges.rceChallenge, () => { return utils.getErrorMessage(err) === 'Infinite loop detected - reached max iterations' })
          next(err)
        }
      }
    } else {
      res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
    }
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
