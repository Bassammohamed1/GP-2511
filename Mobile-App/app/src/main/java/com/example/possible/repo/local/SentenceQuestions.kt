package com.example.possible.repo.local

import com.example.possible.model.SentenceCombining
import com.example.possible.model.SentenceCompleting

object SentenceQuestions {

    private val sentenceCombiningQuestions = listOf(
            SentenceCombining("The cat", "is sleeping", "The cat is sleeping"),
            SentenceCombining("The dog", "barks loud", "The dog barks loud"),
            SentenceCombining("I like", "ice cream", "I like ice cream"),
            SentenceCombining("Birds fly", "in the sky", "Birds fly in the sky"),
            SentenceCombining("The sun", "is hot", "The sun is hot"),
            SentenceCombining("She runs", "very fast", "She runs very fast"),
            SentenceCombining("Tom plays", "with toys", "Tom plays with toys"),
            SentenceCombining("The cake", "is sweet", "The cake is sweet"),
            SentenceCombining("He draws", "a car", "He draws a car"),
            SentenceCombining("The boy", "reads a book", "The boy reads a book"),
            SentenceCombining("Rain falls", "from the sky", "Rain falls from the sky"),
            SentenceCombining("The bird", "sings well", "The bird sings well"),
            SentenceCombining("She paints", "a flower", "She paints a flower"),
            SentenceCombining("The tree", "is tall", "The tree is tall"),
            SentenceCombining("He builds", "a tower", "He builds a tower"),
            SentenceCombining("The horse", "runs fast", "The horse runs fast"),
            SentenceCombining("The fish", "swims deep", "The fish swims deep"),
            SentenceCombining("The sun", "shines bright", "The sun shines bright"),
            SentenceCombining("The stars", "twinkle at night", "The stars twinkle at night"),
            SentenceCombining("He eats", "an apple", "He eats an apple"),
            SentenceCombining("She drinks", "cold milk", "She drinks cold milk"),
            SentenceCombining("The kite", "flies high", "The kite flies high"),
            SentenceCombining("The car", "is red", "The car is red"),
            SentenceCombining("She jumps", "on the bed", "She jumps on the bed"),
            SentenceCombining("The frog", "hops away", "The frog hops away"),
            SentenceCombining("He writes", "a story", "He writes a story"),
            SentenceCombining("The ship", "sails fast", "The ship sails fast"),
            SentenceCombining("The flowers", "smell nice", "The flowers smell nice"),
            SentenceCombining("The book", "is big", "The book is big"),
            SentenceCombining("The snow", "is cold", "The snow is cold"),
            SentenceCombining("The bird", "chirps softly", "The bird chirps softly"),
            SentenceCombining("The train", "moves fast", "The train moves fast"),
            SentenceCombining("She dances", "gracefully", "She dances gracefully"),
            SentenceCombining("The lion", "roars loud", "The lion roars loud"),
            SentenceCombining("He paints", "a house", "He paints a house"),
            SentenceCombining("The water", "is cool", "The water is cool"),
            SentenceCombining("The child", "draws a star", "The child draws a star"),
            SentenceCombining("The apple", "is red", "The apple is red"),
            SentenceCombining("She writes", "a poem", "She writes a poem"),
            SentenceCombining("He builds", "a ship", "He builds a ship"),
            SentenceCombining("The wind", "blows hard", "The wind blows hard"),
            SentenceCombining("The cat", "purrs softly", "The cat purrs softly"),
            SentenceCombining("He sings", "a song", "He sings a song"),
            SentenceCombining("The flowers", "bloom beautifully", "The flowers bloom beautifully"),
            SentenceCombining("The tree", "grows tall", "The tree grows tall"),
            SentenceCombining("The ocean", "is vast", "The ocean is vast"),
            SentenceCombining("The fire", "burns bright", "The fire burns bright"),
            SentenceCombining("The night", "is calm", "The night is calm"),
            SentenceCombining("He catches", "a fish", "He catches a fish"),
            SentenceCombining("She cooks", "a meal", "She cooks a meal"),
            SentenceCombining("The kite", "soars high", "The kite soars high"),
            SentenceCombining("The dog", "wags its tail", "The dog wags its tail"),
            SentenceCombining("She reads", "a book", "She reads a book"),
            SentenceCombining("The river", "flows gently", "The river flows gently"),
            SentenceCombining("He plays", "the guitar", "He plays the guitar"),
            SentenceCombining("The sun", "rises slowly", "The sun rises slowly"),
            SentenceCombining("The moon", "shines bright", "The moon shines bright"),
            SentenceCombining("The child", "laughs loudly", "The child laughs loudly"),
            SentenceCombining("She studies", "her lessons", "She studies her lessons")
    )





    private val sentenceCompletingExamples = listOf(
        SentenceCompleting(
            firstSentence = "The cat climbed the tree",
            secondSentence = "it was chasing a bird",
            theWordToAdd = "because",
            listToChooseFrom = listOf("but", "because", "and", "so")
        ),
        SentenceCompleting(
            firstSentence = "The boy ate his lunch",
            secondSentence = "he was hungry",
            theWordToAdd = "because",
            listToChooseFrom = listOf("and", "but", "because", "so")
        ),
        SentenceCompleting(
            firstSentence = "The girl drew a picture",
            secondSentence = "it was beautiful",
            theWordToAdd = "and",
            listToChooseFrom = listOf("but", "because", "and", "so")
        ),
        SentenceCompleting(
            firstSentence = "They went to the park",
            secondSentence = "it was sunny",
            theWordToAdd = "because",
            listToChooseFrom = listOf("but", "because", "and", "so")
        ),
        SentenceCompleting(
            firstSentence = "The dog barked loudly",
            secondSentence = "it saw a stranger",
            theWordToAdd = "because",
            listToChooseFrom = listOf("and", "but", "because", "so")
        ),
        SentenceCompleting(
            firstSentence = "She went to bed early",
            secondSentence = "she was tired",
            theWordToAdd = "because",
            listToChooseFrom = listOf("but", "because", "and", "so")
        ),
        SentenceCompleting(
            firstSentence = "He opened the window",
            secondSentence = "it was hot inside",
            theWordToAdd = "because",
            listToChooseFrom = listOf("and", "but", "because", "so")
        ),
        SentenceCompleting(
            firstSentence = "The baby laughed",
            secondSentence = "her mom made a funny face",
            theWordToAdd = "because",
            listToChooseFrom = listOf("but", "because", "and", "so")
        ),
        SentenceCompleting(
            firstSentence = "The boy ran fast",
            secondSentence = "he wanted to win",
            theWordToAdd = "because",
            listToChooseFrom = listOf("but", "because", "and", "so")
        ),
        SentenceCompleting(
            firstSentence = "She wore her coat",
            secondSentence = "it was cold outside",
            theWordToAdd = "because",
            listToChooseFrom = listOf("and", "but", "because", "so")
        ),
        SentenceCompleting(
            firstSentence = "The dog barked",
            secondSentence = "it saw a cat",
            theWordToAdd = "because",
            listToChooseFrom = listOf("and", "but", "because", "so")
        ),
        SentenceCompleting(
            firstSentence = "The boy cried",
            secondSentence = "he fell down",
            theWordToAdd = "because",
            listToChooseFrom = listOf("and", "but", "because", "so")
        ),
        SentenceCompleting(
            firstSentence = "The wind blew",
            secondSentence = "the leaves moved",
            theWordToAdd = "and",
            listToChooseFrom = listOf("and", "but", "because", "so")
        ),
        SentenceCompleting(
            firstSentence = "The bird flew",
            secondSentence = "it had wings",
            theWordToAdd = "because",
            listToChooseFrom = listOf("and", "but", "because", "so")
        ),
        SentenceCompleting(
            firstSentence = "The ice melted",
            secondSentence = "it was hot",
            theWordToAdd = "because",
            listToChooseFrom = listOf("and", "but", "because", "so")
        ),
        SentenceCompleting(
            firstSentence = "The car stopped",
            secondSentence = "the driver pressed the brake",
            theWordToAdd = "because",
            listToChooseFrom = listOf("and", "but", "because", "so")
        ),
        SentenceCompleting(
        firstSentence = "The baby cried",
        secondSentence = "it was hungry",
        theWordToAdd = "because",
        listToChooseFrom = listOf("and", "but", "because", "so")
        ),
        SentenceCompleting(
        firstSentence = "The leaf fell",
        secondSentence = "the wind blew it",
        theWordToAdd = "because",
        listToChooseFrom = listOf("and", "but", "because", "so")
        ),
        SentenceCompleting(
        firstSentence = "The cat purred",
        secondSentence = "it was happy",
        theWordToAdd = "because",
        listToChooseFrom = listOf("and", "but", "because", "so")
        ),
        SentenceCompleting(
        firstSentence = "The fish swam away",
        secondSentence = "it was scared",
        theWordToAdd = "because",
        listToChooseFrom = listOf("and", "but", "because", "so")
        )

    )



    fun getRandomCombingSentence(): SentenceCombining{
        return sentenceCombiningQuestions.random()
    }
    fun getRandomCompletingSentence(): SentenceCompleting{
        return sentenceCompletingExamples.random()
    }

}