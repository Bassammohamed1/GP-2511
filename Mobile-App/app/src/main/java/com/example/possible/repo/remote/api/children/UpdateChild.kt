package com.example.possible.repo.remote.api.children

import com.example.possible.repo.remote.response.children.UpdateChildRes
import okhttp3.MultipartBody
import okhttp3.RequestBody
import retrofit2.Response
import retrofit2.http.Header
import retrofit2.http.Multipart
import retrofit2.http.PUT
import retrofit2.http.Part
import retrofit2.http.Path

interface UpdateChild {
    @Multipart
    @PUT("Children/UpdateChild/{id}")
    suspend fun updateChild(
        @Path("id") id:Int,
        @Header("Authorization") token: String,
        @Part("Name") name: RequestBody,
        @Part("Age") age: RequestBody,
        @Part("Gender") gender: RequestBody,
        @Part image: MultipartBody.Part,
        @Part("ParentUserName") parentUserName: RequestBody,
        @Part("Difficult")diff:RequestBody
    ) : Response<UpdateChildRes>
}