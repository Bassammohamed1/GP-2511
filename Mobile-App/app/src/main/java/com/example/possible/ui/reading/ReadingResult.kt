package com.example.possible.ui.reading

import android.annotation.SuppressLint
import android.graphics.Color
import android.os.Bundle
import android.text.Spannable
import android.text.SpannableString
import android.text.style.ForegroundColorSpan
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModelProvider
import com.example.possible.databinding.ActivityReadingResultBinding
import com.example.possible.model.Child
import com.example.possible.repo.local.SharedPref
import com.example.possible.repo.local.database.LocalRepoImp

class ReadingResult : AppCompatActivity() {
    private lateinit var binding: ActivityReadingResultBinding
    private var counter=0
    private var numberOfWords=0
    private lateinit var db: LocalRepoImp
    private lateinit var child: Child
    private lateinit var pref: SharedPref
    private lateinit var viewModeller:ReadingViewModel

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        db = LocalRepoImp(this)
        pref = SharedPref(this)
        viewModeller = ViewModelProvider(this)[ReadingViewModel::class.java]
       binding = ActivityReadingResultBinding.inflate(layoutInflater)
        //get the result of the reading
        val actualText = intent.getStringExtra("actualText")!!
        val speechText = intent.getStringExtra("speechText")!!

        //Toast.makeText(this, speechText, Toast.LENGTH_LONG).show()


        //highlight the correct words and show the result
        //trim the text to remove the spaces at the end
        getResult(speechText,actualText.trim())

        //go back to the previous activity
        binding.backArrowIV.setOnClickListener{
            this.finish()
        }
        //go to the previous activity
        binding.tryAgainBtn.setOnClickListener{
            finish()
        }
        setContentView(binding.root)

    }
    @SuppressLint("ResourceAsColor")
    private fun getResult(text: String, actualWords:String){
        val wordsToCheck = text.split(" ") // Split the text into words
        val correctWords=actualWords.split(" ")
        numberOfWords=correctWords.size
        counter=0

        val range= minOf(wordsToCheck.size,correctWords.size)
        // Create a SpannableString
        val spannableString = SpannableString(actualWords)

        // Apply colors to specific words
        var startIndex = 0
        for (i in 0..<range) {
            val word = wordsToCheck[i]
            val actualWord=correctWords[i]
            val endIndex = startIndex + actualWord.length

            if (areWordsSimilar(word, actualWord)) {
                // Highlight correct words in green
                counter++
                spannableString.setSpan(
                    ForegroundColorSpan(Color.parseColor("#009688")),
                    startIndex,
                    endIndex,
                    Spannable.SPAN_EXCLUSIVE_EXCLUSIVE
                )
            } else{
                // Highlight incorrect words in red
                spannableString.setSpan(
                    ForegroundColorSpan(Color.parseColor("#E91E63")),
                    startIndex,
                    endIndex,
                    Spannable.SPAN_EXCLUSIVE_EXCLUSIVE
                )
            }

            startIndex = endIndex + 1 // Move to the next word (including space)
        }

        binding.yourResult.text= "$counter"
        binding.wordsNumber.text= "$numberOfWords"
        // Set the SpannableString to the TextView
        binding.textOfResult.text=spannableString
        }

    override fun onResume() {
        super.onResume()
        viewModeller.updateReadingRate(this,pref,counter,numberOfWords,db)
    }
    private fun areWordsSimilar(word1: String, word2: String): Boolean {
        val threshold = 1  // لو الفرق حرف واحد أو أقل، هيرجع true

        val distance = levenshteinDistance(word1.lowercase(), word2.lowercase())
        return distance <= threshold
    }

    private fun levenshteinDistance(str1: String, str2: String): Int {
        val dp = Array(str1.length + 1) { IntArray(str2.length + 1) }

        for (i in 0..str1.length) {
            for (j in 0..str2.length) {
                if (i == 0) {
                    dp[i][j] = j
                } else if (j == 0) {
                    dp[i][j] = i
                } else if (str1[i - 1] == str2[j - 1]) {
                    dp[i][j] = dp[i - 1][j - 1]
                } else {
                    dp[i][j] = 1 + minOf(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
                }
            }
        }
        return dp[str1.length][str2.length]
    }



}