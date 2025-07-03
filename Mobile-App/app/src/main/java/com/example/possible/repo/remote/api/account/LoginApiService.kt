package com.example.possible.repo.remote.api.account

import com.example.possible.model.LoginBody
import com.example.possible.repo.remote.response.login.LoginResponse
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.POST

interface LoginApiService {
    @POST("Account/Login")
    suspend fun login(
        @Body loginBody: LoginBody
    ):Response<LoginResponse>
}