package com.example.possible.repo.remote.response.login

data class RegisterResponse(
    val token: String,
    val expiration: String,
    val userId: String,
    val userName: String,
    val email: String,
    val image: String,
    val roles: List<String>
)


