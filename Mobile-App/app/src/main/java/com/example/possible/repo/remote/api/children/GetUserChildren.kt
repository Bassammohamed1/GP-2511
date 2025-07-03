package com.example.possible.repo.remote.api.children

import com.example.possible.model.RemoteChild
import retrofit2.Response
import retrofit2.http.GET
import retrofit2.http.Header

interface GetUserChildren {

    @GET("Children/GetUserChildren")
    suspend fun getUserChildren(
        @Header("Authorization") token: String
    ): Response<List<RemoteChild>>
}
