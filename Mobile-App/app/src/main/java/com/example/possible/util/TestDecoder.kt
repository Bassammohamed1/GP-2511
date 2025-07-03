package com.example.possible.util

import com.example.possible.model.Adding
import com.example.possible.model.SentenceCombining
import com.example.possible.model.SentenceCompleting

object TestDecoder{
    //encode and decode math questions

    //encode and decode adding questions
    fun encodeAdding(adding: Adding): String {
        return "${adding.a} ${adding.b} ${adding.c} ${adding.resultPlaces}"
    }
    fun decodeAdding(encodedString: String): Adding {
        val parts = encodedString.split(" ")
        return Adding(parts[0].toInt(), parts[1].toInt(), parts[2].toInt(), parts[3].toInt())
    }

    //encode and decode arithmetic sequence questions
    fun encodeArithmeticSequence(sequence: List<Int>): String {
        return sequence.joinToString(" ")
    }
    fun decodeArithmeticSequence(encodedString: String): List<Int> {
        return encodedString.split(" ").map { it.toInt() }
    }

    //encode and decode comparison questions
    fun encodeComparison(comparison: Triple<Int, Int, String>): String {
        return "${comparison.first} ${comparison.second} ${comparison.third}"
    }
    fun decodeComparison(encodedString: String): Triple<Int, Int, String> {
        val parts = encodedString.split(" ")
        return Triple(parts[0].toInt(), parts[1].toInt(), parts[2])
    }




    //encode and decode dysgraphia questions

    //write a letter or a number
    fun encodeLetterOrNumber(index: Int, letterOrNumber: String,level:String): String {
        val encodedString = "$index $letterOrNumber $level"
        return encodedString
    }
    fun decodeLetterOrNumber(encodedString: String): Triple<Int, String,String> {
        val parts = encodedString.split(" ")
        val index = parts[0].toInt()
        val letterOrNumber = parts[1]
        return Triple(index,letterOrNumber,parts[2])
    }
    //write a sentence

    //combining sentences
    fun encodeSentenceCombining(sentenceCombining: SentenceCombining): String {
        return "${sentenceCombining.firstSentence};${sentenceCombining.secondSentence};${sentenceCombining.combinedSentence}"
    }
    fun decodeSentenceCombining(encodedString: String): SentenceCombining {
        val parts = encodedString.split(";")
        return SentenceCombining(parts[0], parts[1], parts[2])
    }
    //completing sentences


    fun encodeSentenceCompleting(sentence: SentenceCompleting): String {
        return "${sentence.firstSentence};${sentence.secondSentence};${sentence.theWordToAdd};${sentence.listToChooseFrom.joinToString(",")}"
    }

    fun decodeSentenceCompleting(encodedString: String): SentenceCompleting {
        val parts = encodedString.split(";")
        if (parts.size != 4) throw IllegalArgumentException("Invalid encoded format")

        val firstSentence = parts[0]
        val secondSentence = parts[1]
        val theWordToAdd = parts[2]
        val listToChooseFrom = parts[3].split(",")

        return SentenceCompleting(firstSentence, secondSentence, theWordToAdd, listToChooseFrom)
    }


}