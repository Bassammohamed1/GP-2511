package com.example.possible.repo.remote.api.children

import com.example.possible.model.UpdatedValue
import retrofit2.http.Body
import retrofit2.http.Header
import retrofit2.http.PATCH
import retrofit2.http.Path

interface UpdateReportInf {


    @PATCH("Children/UpdateChildReadingAndWritingDetails/{id}")
    suspend fun updateNewValue(
        @Header("Authorization") token: String,
        @Path("id") childId: String,
        @Body updateReport: List<UpdatedValue>
    ) :retrofit2.Response<UpdateRateResponse>
}