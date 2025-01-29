import { Router } from 'express'
import { sessionController } from './session.module'
import { authenticateJWT } from '../../common/strategies/jwt.strategy'

const sessionRoutes = Router()

sessionRoutes.get('/all', sessionController.getAllSession)
sessionRoutes.get('/', sessionController.getSession)
sessionRoutes.delete('/:id', sessionController.deleteSession)

export default sessionRoutes
