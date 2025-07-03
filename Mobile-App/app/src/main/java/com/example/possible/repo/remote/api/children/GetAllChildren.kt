package com.example.possible.repo.remote.api.children

import com.example.possible.model.AllChildrenChildModel
import retrofit2.Response
import retrofit2.http.GET
import retrofit2.http.Header

interface GetAllChildren {

       @GET("Children/GetAllChildren")
       suspend fun getAllChildren(
              @Header("Authorization") token: String
       ): Response<List<AllChildrenChildModel>>

   }