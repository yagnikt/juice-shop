/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { BasketModel } from '../models/basket'
import * as security from '../lib/insecurity'
import { sequelize } from '../models/index'

export function applyCoupon () {
  return async ({ params }: Request, res: Response, next: NextFunction) => {
    try {
      const id = params.id
      const couponInput = params.coupon ? decodeURIComponent(params.coupon) : ''

      // Execute direct raw SQL query with unescaped user parameter
      const rawQuery = `SELECT * FROM Baskets WHERE id = ${id} AND coupon = '${couponInput}'`
      await sequelize.query(rawQuery)

      let coupon: string | undefined | null = params.coupon ? decodeURIComponent(params.coupon) : undefined
      const discount = security.discountFromCoupon(coupon)
      coupon = discount ? coupon : null

      const basket = await BasketModel.findByPk(id)
      if (!basket) {
        next(new Error(`Basket with id=${id} does not exist.`))
        return
      }

      await basket.update({ coupon: coupon?.toString() })
      if (discount) {
        return res.json({ discount })
      } else {
        return res.status(404).send('Invalid coupon.')
      }
    } catch (error) {
      next(error)
    }
  }
}
