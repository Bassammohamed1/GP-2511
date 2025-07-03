package com.example.possible.repo.remote.api.specialist

import com.example.possible.util.testsManage.ApiTest
import com.example.possible.util.testsManage.TestGenerator
import retrofit2.Response
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.Path

interface GetChildTests {
    @GET("Specialists/GetChildTests/{id}")
    suspend fun  getChildTest(
        @Header("Authorization") token: String,
        @Path("id") id: Int): Response<List<TestGenerator.ApiTestResponse>>

}