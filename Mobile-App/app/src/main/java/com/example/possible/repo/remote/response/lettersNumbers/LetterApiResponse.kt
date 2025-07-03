package com.example.possible.repo.remote.response.lettersNumbers

sealed class LetterApiResponse{
    data class Success(val character: Char,
                       val prediction: String)
        : LetterApiResponse()
    data class Error(
        val prediction: String
    ): LetterApiResponse()
}
