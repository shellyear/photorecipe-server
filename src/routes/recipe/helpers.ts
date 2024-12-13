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

export interface RequestBody {
  image: File
  recipeChoice: RecipeChoice
  skillLevel?: SkillLevel
  timeConstraint?: TimeConstraint
  dietaryRestrictions?: string // Json parsed string array in form data
  missingIngredients?: string
}

export type FormattedRequestBody = Omit<RequestBody, 'dietaryRestrictions'> & {
  dietaryRestrictions?: string[]
}

export function convertBufferToBase64(image: Express.Multer.File): string {
  // Convert the image buffer to Base64
  const base64String = image.buffer.toString('base64')

  // Return a Data URL with the proper mime type (e.g., image/jpeg)
  return `data:${image.mimetype};base64,${base64String}`
}

export function getDishRecipePrompt() {
  return 'Here is an image of a dish. Analyze it and provide a recipe.'
}

export function getIngredientsRecipePrompt({
  skillLevel,
  timeConstraint,
  dietaryRestrictions,
  missingIngredients
}: Pick<
  FormattedRequestBody,
  'skillLevel' | 'timeConstraint' | 'dietaryRestrictions' | 'missingIngredients'
>) {
  return `Give me a recipe for the ingredients on the photo. Missing ingredients on the photo: ${missingIngredients} Cooking time: ${timeConstraint}. Skill level: ${skillLevel}. ${
    dietaryRestrictions?.length
      ? `Dietary restrictions: ${dietaryRestrictions.map((restriction) => restriction).join(', ')}`
      : ''
  }.`
}

export function getPrompt(
  recipeChoice: RecipeChoice.DISH | RecipeChoice.INGREDIENTS,
  recipeOptions: Pick<
    FormattedRequestBody,
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
