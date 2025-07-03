package com.example.possible.repo.remote.api.children

import com.example.possible.repo.remote.response.children.AddChildResponse
import okhttp3.MultipartBody
import okhttp3.RequestBody
import retrofit2.Call
import retrofit2.Response
import retrofit2.http.Header
import retrofit2.http.Multipart
import retrofit2.http.POST
import retrofit2.http.Part

interface AddChild {
    @Multipart
    @POST("Children/AddChild")
    suspend fun addChild(
        @Header("Authorization") token: String,
        @Part("Name") name: RequestBody,
        @Part("Age") age: RequestBody,
        @Part("Gender") gender: RequestBody,
        @Part image: MultipartBody.Part,
        @Part("ParentUserName") parentUserName: RequestBody,
        @Part("Difficult")diff:RequestBody

    ): Response<AddChildResponse>
}