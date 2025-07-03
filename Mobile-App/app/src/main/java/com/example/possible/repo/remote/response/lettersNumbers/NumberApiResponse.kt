package com.example.possible.repo.remote.response.lettersNumbers

import com.google.gson.annotations.SerializedName

class NumberApiResponse (
    @SerializedName("predicted_class")
    val predicted_class: Int
)