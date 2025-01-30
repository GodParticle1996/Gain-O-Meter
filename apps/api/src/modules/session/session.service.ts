import { NotFoundException } from '../../common/utils/catch-errors'
import SessionModel from '../../database/models/session.model'

export class SessionService {
  /*
The code uses a SessionModel to find all sessions that match two conditions:
1. They belong to the given userId
2. They haven't expired yet (expiredAt date is greater than the current time)

When searching for these sessions, it requests five pieces of information for each session:
1. The session ID (_id)
2. The user ID (userId)
3. The browser/device info (userAgent)
4. When the session was created (createdAt)
5. When the session will expire (expiredAt)

The results are sorted by createdAt in descending order (-1), which means the newest sessions appear first in the list.
*/
  public async getAllSession(userId: string) {
    const sessions = await SessionModel.find(
      {
        userId,
        expiredAt: { $gt: Date.now() },
      },
      {
        _id: 1,
        userId: 1,
        userAgent: 1,
        createdAt: 1,
        expiredAt: 1,
      },
      {
        sort: {
          createdAt: -1,
        },
      },
    )

    return {
      sessions,
    }
  }

  public async getSessionById(sessionId: string) {
    const session = await SessionModel.findById(sessionId)
      .populate('userId')
      .select('-expiresAt')
    // The select("-expiresAt") is used to exclude the expiresAt field from the result.

    if (!session) {
      throw new NotFoundException('Session not found')
    }
    const { userId: user } = session

    return {
      user,
    }
  }

  public async deleteSession(sessionId: string, userId: string) {
    const deletedSession = await SessionModel.findByIdAndDelete({
      _id: sessionId,
      userId: userId,
    })
    if (!deletedSession) {
      throw new NotFoundException('Session not found')
    }
    return
  }
}
