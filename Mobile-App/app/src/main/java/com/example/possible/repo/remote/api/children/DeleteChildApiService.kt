package com.example.possible.repo.remote.api.children

import com.example.possible.repo.remote.response.children.DeleteChildResponse
import retrofit2.Response
import retrofit2.http.DELETE
import retrofit2.http.Header
import retrofit2.http.Path

interface DeleteChildApiService {

    @DELETE("Children/DeleteChild/{id}")
   suspend fun deleteChild(
        @Header("Authorization") token: String,
        @Path("id") id: Int
    ): Response<DeleteChildResponse>
}
