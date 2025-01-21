import mongoose from 'mongoose'
import { config } from '../config/app.config'

const connectDatabase = async () => {
  try {
    console.log('config.MONGO_URI', config.MONGO_URI)
    await mongoose.connect(config.MONGO_URI)
    console.log('Connected to Mongo database')
  } catch (error) {
    console.log('error', error)
    console.log('Error connecting to Mongo database')
    process.exit(1)
  }
}

export default connectDatabase
