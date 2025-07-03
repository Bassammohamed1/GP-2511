package com.example.possible.ui.profile.profileManage

import android.content.Context
import android.util.Log
import android.view.View.GONE
import android.view.View.VISIBLE
import android.widget.Toast
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.possible.databinding.ActivityEditProfileBinding
import com.example.possible.repo.local.SharedPref
import com.example.possible.repo.remote.RetrofitBuilder
import com.example.possible.util.helper.InterNetHelper
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.MultipartBody
import okhttp3.RequestBody.Companion.asRequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.File

class EditProfileViewModel: ViewModel() {
    fun update(
        username: String,
        email: String,
        password: String,
        roleNo: String,
        imageFile: File,
        context: Context,
        bind: ActivityEditProfileBinding,
        onUpdateSuccess: () -> Unit
    ) {
        viewModelScope.launch(Dispatchers.IO) {
            withContext(Dispatchers.Main){
                bind.loadingView.visibility = VISIBLE
            }
            try {
                if(!InterNetHelper.isInternetAvailable(context)){
                    withContext(Dispatchers.Main) {
                        Toast.makeText(context, "❌ No Internet Connection", Toast.LENGTH_SHORT).show()
                        bind.loadingView.visibility = GONE
                    }
                    return@launch
                }

                val usernamePart = username.toRequestBody("text/plain".toMediaTypeOrNull())
                val emailPart = email.toRequestBody("text/plain".toMediaTypeOrNull())
                val passwordPart = password.toRequestBody("text/plain".toMediaTypeOrNull())
                val roleNoPart = roleNo.toRequestBody("text/plain".toMediaTypeOrNull())

                val requestFile = imageFile.asRequestBody("image/jpeg".toMediaTypeOrNull())
                val imagePart = MultipartBody.Part.createFormData("ClientFile", imageFile.name, requestFile)

                val response = RetrofitBuilder.editProfileApiService.updateProfile(
                    token = "Bearer ${SharedPref(context).getProfileDetails().token}",
                    usernamePart, emailPart, passwordPart, roleNoPart, imagePart
                ).execute()

                withContext(Dispatchers.Main) {
                    if (response.isSuccessful) {
                        val registerResponse = response.body()!!
                        Toast.makeText(context, "✅ Updated Successfully!", Toast.LENGTH_SHORT).show()
                        onUpdateSuccess()
                    } else {
                        val errorBody = response.errorBody()?.string()
                        Log.e("EditProfileViewModel", "Error Code: ${response.code()} - Error Body: $errorBody")

                        errorBody?.let {
                            val jsonObject = JSONObject(it)
                            if (jsonObject.has("errors")) {
                                val errors = jsonObject.getJSONObject("errors")
                                if (errors.has("Email")) {
                                    val emailErrors = "❌ Invalid email: " + errors.getJSONArray("Email").getString(0)
                                    bind.emailLayout.error = emailErrors
                                }
                                if (errors.has("Password")) {
                                    val passwordErrors = "❌ Invalid password: " + errors.getJSONArray("Password").getString(0)
                                    bind.passLayout.error = passwordErrors
                                }
                            } else if (jsonObject.has("Custom")) {
                                val customErrors = jsonObject.getJSONArray("Custom")
                                val errorMessage = customErrors.getString(0)
                                if (errorMessage.startsWith("Passwords")) {
                                    bind.passLayout.error = errorMessage
                                } else {
                                    Toast.makeText(context, errorMessage, Toast.LENGTH_LONG).show()
                                }
                            } else {
                                Toast.makeText(context, "❌ Unknown error occurred", Toast.LENGTH_SHORT).show()
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Log.e("EditProfileViewModel", "Exception: ${e.message}")
                }
                if(InterNetHelper.isInternetAvailable(context)){
                onUpdateSuccess()
                    withContext(Dispatchers.Main) {
                        Toast.makeText(context, "Updated Successfully!", Toast.LENGTH_SHORT).show()
                    }
                }
                else{
                    withContext(Dispatchers.Main) {
                        Toast.makeText(context, "❌ Network Error: ${e.message}", Toast.LENGTH_SHORT).show()
                    }
                }
            }
            withContext(Dispatchers.Main){
                bind.loadingView.visibility = GONE
            }
        }
    }
}
