package com.example.possible.repo.remote.api.aiPrediction

import com.example.possible.repo.remote.response.lettersNumbers.LetterApiResponse
import okhttp3.MultipartBody
import retrofit2.Response
import retrofit2.http.Multipart
import retrofit2.http.POST
import retrofit2.http.Part


interface PredictLetterApiService {
    @Multipart
    @POST("predict")
    suspend fun uploadLetterImage(
        @Part image: MultipartBody.Part
    ): Response<LetterApiResponse>
}
