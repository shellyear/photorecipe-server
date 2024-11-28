import { zodResponseFormat } from 'openai/helpers/zod'
import { z } from 'zod'
import axios from 'axios'
import express, { Request } from 'express'

export enum TimeConstraint {
  HALF_HOUR = '30 minutes or less',
  HOUR = '1 hour or less',
  HOUR_AND_HALF = '1,5 hours or less',
  ANY = 'any time'
}

export enum SkillLevel {
  BEGINNER = 'beginner',
  INTERMEDIATE = 'intermediate',
  ADVANCED = 'advanced'
}

export enum RecipeChoice {
  DISH = 'dish',
  INGREDIENTS = 'ingredients'
}

interface RequestBody {
  image: Buffer
  recipeChoice: RecipeChoice
  skillLevel?: SkillLevel
  timeConstraint?: TimeConstraint
  dietaryRestrictions?: string[]
  missingIngredients?: string
}

function getDishRecipePrompt() {
  return 'Here is an image of a dish. Analyze it and provide a recipe.'
}

function getIngredientsRecipePrompt({
  skillLevel,
  timeConstraint,
  dietaryRestrictions,
  missingIngredients
}: Pick<
  RequestBody,
  'skillLevel' | 'timeConstraint' | 'dietaryRestrictions' | 'missingIngredients'
>) {
  return `Give me a recipe for the ingredients on the photo. Missing ingredients on the photo: ${missingIngredients} Cooking time: ${timeConstraint}. Skill level: ${skillLevel}. ${
    dietaryRestrictions?.length
      ? `Dietary restrictions: ${dietaryRestrictions.map((restriction) => restriction).join(', ')}`
      : ''
  }.`
}

function getPrompt(
  recipeChoice: RecipeChoice.DISH | RecipeChoice.INGREDIENTS,
  recipeOptions: Pick<
    RequestBody,
    | 'skillLevel'
    | 'timeConstraint'
    | 'dietaryRestrictions'
    | 'missingIngredients'
  >
) {
  if (recipeChoice === RecipeChoice.DISH) {
    return getDishRecipePrompt()
  }

  if (recipeChoice === RecipeChoice.INGREDIENTS) {
    return getIngredientsRecipePrompt({
      ...recipeOptions
    })
  }

  return ''
}

const RecipeFormat = z.object({
  name: z.string(),
  ingredients: z.array(z.string()),
  instructions: z.array(z.string())
})

const router = express.Router()

router.post('/', async (req: Request<object, object, RequestBody>, res) => {
  const {
    image,
    recipeChoice,
    skillLevel,
    timeConstraint,
    dietaryRestrictions,
    missingIngredients
  }: RequestBody = req.body

  const promptText = getPrompt(recipeChoice, {
    skillLevel,
    timeConstraint,
    dietaryRestrictions,
    missingIngredients
  })

  try {
    const url = 'https://api.openai.com/v1/chat/completions'
    const options = {
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${process.env.OPENAI_API_KEY}`
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
                url: image,
                detail: 'low'
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
    res.json(response.data.choices[0].message.content)
  } catch (error) {
    console.error('Error fetching from OpenAI:', error)
    res.status(500).json({ error: 'Failed to fetch recipe' })
  }
})

export default router
