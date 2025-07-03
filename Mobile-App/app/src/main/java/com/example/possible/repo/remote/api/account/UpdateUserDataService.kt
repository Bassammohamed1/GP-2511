package com.example.possible.repo.remote.api.account

import okhttp3.MultipartBody
import okhttp3.RequestBody
import okhttp3.ResponseBody
import retrofit2.Call
import retrofit2.http.Header
import retrofit2.http.Multipart
import retrofit2.http.PUT
import retrofit2.http.Part

interface UpdateUserDataService {
        @Multipart
        @PUT("Account/UpdateUser")
        suspend fun updateProfile(
            @Header("Authorization") token: String,
            @Part("Username") name: RequestBody,
            @Part("Email") email: RequestBody,
            @Part("Password") password: RequestBody,
            @Part("RoleNo") roleNo: RequestBody,
            @Part image: MultipartBody.Part // الصورة إجبارية
        ): Call<ResponseBody>

}


