package com.example.possible.model

data class SentenceCompleting(
    val firstSentence: String,
    val secondSentence: String,
    val theWordToAdd: String,
    val listToChooseFrom: List<String>
)
