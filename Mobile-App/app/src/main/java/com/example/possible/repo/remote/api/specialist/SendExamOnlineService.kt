package com.example.possible.repo.remote.api.specialist

import com.example.possible.util.testsManage.ApiTest
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.Header
import retrofit2.http.POST

interface SendExamOnlineService {
    @POST("Specialists/CreateTest")
    suspend fun sendExamOnline(
        @Header("Authorization") token: String,
        @Body exam: ApiTest): Response<CreateExamResponse>
}