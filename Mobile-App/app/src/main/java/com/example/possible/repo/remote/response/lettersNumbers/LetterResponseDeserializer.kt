package com.example.possible.repo.remote.response.lettersNumbers

import com.google.gson.*
import java.lang.reflect.Type

class LetterResponseDeserializer : JsonDeserializer<LetterApiResponse> {
    override fun deserialize(
        json: JsonElement,
        typeOfT: Type,
        context: JsonDeserializationContext
    ): LetterApiResponse {
        val jsonObject = json.asJsonObject

        return if (jsonObject.has("character")) {
            context.deserialize(jsonObject, LetterApiResponse.Success::class.java)
        } else {
            context.deserialize(jsonObject, LetterApiResponse.Error::class.java)
        }
    }
}
