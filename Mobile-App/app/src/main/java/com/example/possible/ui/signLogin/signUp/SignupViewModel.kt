package com.example.possible.ui.signLogin.signUp

import android.content.Context
import android.view.View.GONE
import android.view.View.VISIBLE
import android.widget.Toast
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.possible.databinding.ActivitySignupBinding
import com.example.possible.repo.local.SharedPref
import com.example.possible.repo.remote.RetrofitBuilder
import com.example.possible.util.LogoutHandler
import com.example.possible.util.helper.dataManager.AppDataManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.MultipartBody
import okhttp3.RequestBody.Companion.asRequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.File

class SignupViewModel : ViewModel() {

      fun signUpUserSync(
         username: String,
         email: String,
         password: String,
         roleNo: String,
         imageFile: File,
         context: Context,
         bind:ActivitySignupBinding,
         onSignUpSuccess: () -> Unit
     ) {
         viewModelScope.launch(Dispatchers.IO) {
             withContext(Dispatchers.Main){
                 bind.loadingView.visibility = VISIBLE
             }
             try {
                 val usernamePart = username.toRequestBody("text/plain".toMediaTypeOrNull())
                 val emailPart = email.toRequestBody("text/plain".toMediaTypeOrNull())
                 val passwordPart = password.toRequestBody("text/plain".toMediaTypeOrNull())
                 val roleNoPart = roleNo.toRequestBody("text/plain".toMediaTypeOrNull())

                 val requestFile = imageFile.asRequestBody("image/jpeg".toMediaTypeOrNull())
                 val imagePart = MultipartBody.Part.createFormData("ClientFile", imageFile.name, requestFile)

                 val response = RetrofitBuilder.registerApiService.registerUser(
                     usernamePart, emailPart, passwordPart, roleNoPart, imagePart)
                     .execute()

                 withContext(Dispatchers.Main) {
                     if (response.isSuccessful) {
                         val registerResponse = response.body()!!
                         Toast.makeText(context, "✅ SignUp Successfully!", Toast.LENGTH_SHORT).show()
                         onSignUpSuccess()
                         val image = registerResponse.image
                         val token = registerResponse.token
                         val userId = registerResponse.userId
                         val expiration = registerResponse.expiration
                         val role = registerResponse.roles[0]
                         AppDataManager.saveProfileData(
                             context,
                             SharedPref(context),
                             image,
                             username,
                             email,
                             password,
                             expiration,
                             token,
                             userId,
                             role
                         )

                         //saveData(SharedPref(context),registerResponse.image,registerResponse.userName,registerResponse.email,registerResponse.password)
                     } else {
                         val errorBody = response.errorBody()?.string()
                         errorBody?.let {
                             val jsonObject = JSONObject(it)
                             if (jsonObject.has("errors")) {
                                 val errors = jsonObject.getJSONObject("errors")
                                 if (errors.has("Email")) {
                                     val emailErrors = "❌ invalid email: " + errors.getJSONArray("Email").getString(0)
                                     withContext(Dispatchers.Main) {
                                         bind.emailLayout.error = emailErrors
                                     }

                                 }
                                 if (errors.has("Password")) {
                                     val passwordErrors = "❌ invalid password: " + errors.getJSONArray("Password").getString(0)
                                     withContext(Dispatchers.Main) {
                                         bind.passLayout.error = passwordErrors
                                     }
                                 }
                             } else if (jsonObject.has("Custom")) {
                                 val customErrors = jsonObject.getJSONArray("Custom")
                                 val errorMessage = customErrors.getString(0)
                                 if (errorMessage.split(" ")[0]=="Passwords")  {
                                     withContext(Dispatchers.Main) {
                                         bind.passLayout.error = errorMessage
                                     }
                                 }
                                 else {
                                     withContext(Dispatchers.Main) {
                                         Toast.makeText(context,errorMessage, Toast.LENGTH_LONG).show()
                                     }
                                 }
                             }
                         }
                     }
                 }
             } catch (e: Exception) {
                 withContext(Dispatchers.Main) {
                     Toast.makeText(context, "❌ Network Error: ${e.message}", Toast.LENGTH_SHORT).show()
                 }
             }
             withContext(Dispatchers.Main){
                 bind.loadingView.visibility = GONE
             }
         }
     }


    }
