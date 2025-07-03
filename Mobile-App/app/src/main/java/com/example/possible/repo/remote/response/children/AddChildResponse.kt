package com.example.possible.repo.remote.response.children

data class AddChildResponse(
    val  id : Int,
    val name :String,
    val age :Int,
    val difficult :String,
    val parentId :String,
    val gender :Int,
    val image :String)
