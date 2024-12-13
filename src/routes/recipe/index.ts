import express, { Request, Response } from 'express'
import multer from 'multer'
import { zodResponseFormat } from 'openai/helpers/zod'
import { z } from 'zod'
import axios from 'axios'
import { convertBufferToBase64, getPrompt } from './helpers'
import { RequestBody } from './helpers'
import Config from '../../config'
import { verifyJWT } from '../../middlewares/auth'

const RecipeFormat = z.object({
  name: z.string(),
  ingredients: z.array(z.string()),
  instructions: z.array(z.string())
})

const router = express.Router()
const storage = multer.memoryStorage()
const upload = multer({ storage })

router.post(
  '/',
  verifyJWT,
  upload.single('image'),
  async (req: Request<object, object, RequestBody>, res: Response) => {
    const image = req.file
    const {
      recipeChoice,
      skillLevel,
      timeConstraint,
      dietaryRestrictions,
      missingIngredients
    }: RequestBody = req.body

    const parsedDietaryRestrictions = JSON.parse(
      dietaryRestrictions || ''
    ) as string[]

    const promptText = getPrompt(recipeChoice, {
      skillLevel,
      timeConstraint,
      dietaryRestrictions: parsedDietaryRestrictions,
      missingIngredients
    })

    if (!image) {
      return
    }

    try {
      const url = 'https://api.openai.com/v1/chat/completions'
      const options = {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${Config.OPENAI_API_KEY}`
        }
      }
      const body = JSON.stringify({
        model: 'gpt-4o-mini',
        messages: [
          {
            role: 'user',
            content: [
              { type: 'text', text: promptText },
              {
                type: 'image_url',
                image_url: {
                  url: convertBufferToBase64(image)
                  // detail: 'low'
                }
              }
            ]
          }
        ],
        max_completion_tokens: 400,
        /**
         * How many chat completion choices to generate for each input message. Note that
         * you will be charged based on the number of generated tokens across all of the
         * choices. Keep `n` as `1` to minimize costs.
         */
        response_format: zodResponseFormat(RecipeFormat, 'recipe')
      })
      const response = await axios.post(url, body, options)
      console.log('Token usage', response?.data.usage)
      const data = JSON.parse(response.data.choices[0].message.content)
      res.status(200).json({
        data
      })
    } catch (error: any) {
      console.error('Error fetching from OpenAI:', error?.message)
      res
        .status(500)
        .json({ message: `Failed to fetch recipe: ${error?.message}` })
    }
  }
)

export default router
