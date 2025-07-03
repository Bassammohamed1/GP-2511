package com.example.possible.repo.local

import com.example.possible.model.Adding

object MathQuestions {

     val simpleAddition = arrayListOf(
        Adding(10, 20, 30,2),         // Simple two-digit addition
        Adding(5, 5, 10,2),           // Single-digit numbers
        Adding(8, 7, 15,2),           // Two single-digit numbers, no carrying
        Adding(20, 30, 50,2),         // Two-digit addition with no carrying
        Adding(12, 15, 27,2),         // Small numbers, one step of thinking
        Adding(7, 8, 15,2),           // Easy single-digit addition
        Adding(40, 20, 60,2),         // Clean addition with no surprises
        Adding(25, 25, 50,2),         // Half-and-half two-digit numbers
        Adding(30, 10, 40,2),         // Straightforward tens addition
        Adding(11, 22, 33,2),         // Easy addition with clear results
        Adding(50, 25, 75,2),         // Two-digit addition
        Adding(6, 9, 15,2),           // Single-digit numbers
        Adding(15, 10, 25,2),         // Small two-digit numbers
        Adding(8, 12, 20,2),          // Small numbers, simple steps
        Adding(5, 15, 20,2),          // Single- and two-digit combo
        Adding(10, 5, 15,2),          // Simple and quick to solve
        Adding(9, 6, 15,2),           // No carrying, single digits
        Adding(20, 5, 25,2),          // Two-digit with single-digit
        Adding(10, 10, 20,2),         // Symmetrical addition
        Adding(18, 2, 20,2),          // Just breaking into tens
        Adding(12, 8, 20,2),          // Close numbers for balance
        Adding(30, 20, 50,2),         // Simple double-digit addition
        Adding(7, 3, 10,2),           // Single digits rounding to ten
        Adding(9, 1, 10,2),           // Very basic addition
        Adding(4, 6, 10,2)            // Easy single-digit problem
    )

     val proAddition = arrayListOf(
        Adding(234, 567, 801,3),       // Three-digit numbers with carrying in one column
        Adding(123, 456, 579,3),       // Sequential three-digit addition
        Adding(3456, 1234, 4690,4),    // Four-digit addition with moderate carrying
        Adding(789, 876, 1665,4),      // Close three-digit numbers
        Adding(1500, 2500, 4000,4),    // Clean, simple addition
        Adding(4567, 2345, 6912,4),    // Four-digit numbers with irregular digits
        Adding(3000, 4500, 7500,4),    // Simple carrying with thousands
        Adding(1234, 4321, 5555,4),    // Numbers with mirrored digits
        Adding(987, 654, 1641,4),      // Three-digit addition with carrying
        Adding(5678, 4321, 9999,4),    // Four-digit numbers adding up to an edge case
        Adding(890, 1234, 2124,4),     // Three- and four-digit combination
        Adding(6789, 1234, 8023,4),    // Four-digit numbers with minimal carrying
        Adding(555, 444, 999,3),       // Three-digit addition with complete carrying
        Adding(1200, 3500, 4700,4),    // Simple addition with thousands
        Adding(999, 888, 1887,4),      // Challenging three-digit numbers
        Adding(4321, 1234, 5555,4),    // Clean four-digit pattern
        Adding(7890, 1230, 9120,4),    // Four-digit addition with no surprises
        Adding(3333, 6666, 9999,4),    // Balanced carrying across all columns
        Adding(5678, 8765, 14443,5),   // Larger four-digit addition with carrying
        Adding(3456, 2345, 5801,4),    // Four-digit numbers with moderate difficulty
        Adding(1001, 2002, 3003,4),    // Balanced numbers
        Adding(678, 789, 1467,4),      // Three-digit carrying problem
        Adding(12345, 6789, 19134,5),  // Five-digit addition with moderate carrying
        Adding(8000, 7000, 15000,5),   // Larger numbers with simple carrying
        Adding(9001, 2345, 11346,5)    // Four-digit addition with some complexity
    )

     val simpleSubtraction = arrayListOf(
        Adding(10, 5, 5, 1),         // Simple single-digit result
        Adding(20, 10, 10, 2),       // Two-digit result with no borrowing
        Adding(15, 7, 8, 1),         // Single-digit result
        Adding(30, 20, 10, 2),       // Two-digit result, clean subtraction
        Adding(50, 25, 25, 2),       // Two-digit result, balanced numbers
        Adding(100, 50, 50, 2),      // Two-digit result, no borrowing
        Adding(18, 9, 9, 1),         // Single-digit result, no carrying
        Adding(25, 10, 15, 2),       // Two-digit result with straightforward subtraction
        Adding(40, 30, 10, 2),       // Two-digit result, simple calculation
        Adding(12, 4, 8, 1),         // Single-digit result, basic subtraction
        Adding(22, 11, 11, 2),       // Two-digit result, mirrored numbers
        Adding(17, 8, 9, 1),         // Single-digit result with moderate thought
        Adding(35, 20, 15, 2),       // Two-digit result, clean subtraction
        Adding(60, 30, 30, 2),       // Two-digit result, round numbers
        Adding(45, 15, 30, 2),       // Two-digit result with clear steps
        Adding(14, 7, 7, 1),         // Single-digit result, balanced numbers
        Adding(20, 5, 15, 2),        // Two-digit result, small difference
        Adding(90, 45, 45, 2),       // Two-digit result, symmetrical numbers
        Adding(12, 6, 6, 1),         // Single-digit result
        Adding(100, 25, 75, 2),      // Two-digit result, simple subtraction
        Adding(50, 20, 30, 2),       // Two-digit result with no surprises
        Adding(80, 40, 40, 2),       // Two-digit result, even numbers
        Adding(27, 14, 13, 2),       // Two-digit result, clean subtraction
        Adding(19, 9, 10, 2),        // Two-digit result, close numbers
        Adding(95, 40, 55, 2)     // Three-digit result, straightforward
    )

     val proSubtraction = arrayListOf(
        Adding(345,123, 222, 3),      // Three-digit subtraction with borrowing
        Adding(567,234, 333, 3),      // Simple borrowing, three-digit numbers
        Adding(1234,678, 556, 3),     // Four-digit minus three-digit, three-digit result
        Adding(890,123, 767, 3),      // Three-digit numbers with borrowing
        Adding(5678,1234, 4444, 4),   // Larger numbers with multiple steps of borrowing
        Adding(876,234, 642, 3),      // Simple three-digit subtraction with borrowing
        Adding(1000,567, 433, 3),     // Four-digit minus three-digit, three-digit result
        Adding(789,456, 333, 3),      // Three-digit subtraction with a straightforward result
        Adding(950,400, 550, 3),      // Mid-range subtraction with no surprise
        Adding(1345,678, 667, 3),     // Four-digit numbers, three-digit result with borrowing
        Adding(2500,1234, 1266, 4),   // Large numbers with minor borrowing
        Adding(8765,4321, 4444, 4),   // Larger subtraction problem
        Adding(5000,2334, 2666, 4),   // Four-digit subtraction with balanced numbers
        Adding(6543,4321, 2222, 4),   // Four-digit numbers, involves borrowing
        Adding(765,432, 333, 3),      // Three-digit subtraction with borrowing
        Adding(800,370, 430, 3),      // Mid-range numbers, clean subtraction
        Adding(1234,999, 235, 3),     // Four-digit minus three-digit with borrowing
        Adding(2500,1250, 1250, 4),   // Clean subtraction with round numbers
        Adding(9500,4231, 5269, 4),   // Large subtraction with moderate difficulty
        Adding(6400, 2345, 4055, 4),   // Four-digit subtraction with borrowing
        Adding(798, 456, 342, 3),      // Three-digit subtraction, one borrowing step
        Adding(4321, 1234, 3087, 4),   // Large numbers with a moderate challenge
        Adding(1200, 875, 325, 3),     // Four-digit minus three-digit with borrowing
        Adding(8000, 2345, 5655, 4)    // Large subtraction with a clean result
    )
   val simpleComparisons = listOf(
      Triple(1, 2, "<"),    // Example 1: 1 is less than 2
      Triple(100, 100, "="), // Example 2: 100 is equal to 100
      Triple(10, 8, ">"),    // Example 3: 10 is greater than 8
      Triple(5, 15, "<"),    // Example 4: 5 is less than 15
      Triple(50, 25, ">"),   // Example 5: 50 is greater than 25
      Triple(200, 200, "="), // Example 6: 200 is equal to 200
      Triple(0, 1, "<"),     // Example 7: 0 is less than 1
      Triple(20, 30, "<"),   // Example 8: 20 is less than 30
      Triple(7, 7, "="),     // Example 9: 7 is equal to 7
      Triple(12, 24, "<"),   // Example 10: 12 is less than 24
      Triple(300, 150, ">"), // Example 11: 300 is greater than 150
      Triple(10, 5, ">"),    // Example 12: 10 is greater than 5
      Triple(500, 600, "<"), // Example 13: 500 is less than 600
      Triple(5, 10, "<"),    // Example 14: 5 is less than 10
      Triple(150, 100, ">"), // Example 15: 150 is greater than 100
      Triple(2, 4, "<"),     // Example 16: 2 is less than 4
      Triple(1000, 500, ">"),// Example 17: 1000 is greater than 500
      Triple(18, 18, "="),   // Example 18: 18 is equal to 18
      Triple(30, 25, ">"),   // Example 19: 30 is greater than 25
      Triple(8, 12, "<"),    // Example 20: 8 is less than 12
      Triple(60, 50, ">"),   // Example 21: 60 is greater than 50
      Triple(90, 95, "<"),   // Example 22: 90 is less than 95
      Triple(7, 20, "<"),    // Example 23: 7 is less than 20
      Triple(2000, 1500, ">"),// Example 24: 2000 is greater than 1500
      Triple(6, 9, "<"),     // Example 25: 6 is less than 9
      Triple(40, 40, "="),   // Example 26: 40 is equal to 40
      Triple(3000, 5000, "<"),// Example 27: 3000 is less than 5000
      Triple(400, 300, ">"), // Example 28: 400 is greater than 300
      Triple(70, 60, ">"),   // Example 29: 70 is greater than 60
      Triple(250, 250, "=")  // Example 30: 250 is equal to 250
   )
   val proComparisons = listOf(
      Triple(1245, 5678, "<"),          // Example 1: 1245 is less than 5678
      Triple(9876, 9876, "="),          // Example 2: 9876 is equal to 9876
      Triple(1024, 2048, "<"),          // Example 3: 1024 is less than 2048
      Triple(5467, 1234, ">"),          // Example 4: 5467 is greater than 1234
      Triple(7654, 5432, ">"),          // Example 5: 7654 is greater than 5432
      Triple(15000, 10000, ">"),        // Example 6: 15000 is greater than 10000
      Triple(2147483647, 1073741824, ">"), // Example 7: 2147483647 is greater than 1073741824
      Triple(5000, 4500, ">"),          // Example 8: 5000 is greater than 4500
      Triple(3333, 4444, "<"),          // Example 9: 3333 is less than 4444
      Triple(500, 5000, "<"),           // Example 10: 500 is less than 5000
      Triple(123456, 654321, "<"),      // Example 11: 123456 is less than 654321
      Triple(1000000, 999999, ">"),     // Example 12: 1000000 is greater than 999999
      Triple(987654321, 123456789, ">"), // Example 13: 987654321 is greater than 123456789
      Triple(800000, 400000, ">"),      // Example 14: 800000 is greater than 400000
      Triple(555555, 555555, "="),      // Example 15: 555555 is equal to 555555
      Triple(99999, 100000, "<"),       // Example 16: 99999 is less than 100000
      Triple(33333, 66666, "<"),        // Example 17: 33333 is less than 66666
      Triple(999, 1000, "<"),           // Example 18: 999 is less than 1000
      Triple(90876, 90877, "<"),        // Example 19: 90876 is less than 90877
      Triple(9999, 8888, ">"),          // Example 20: 9999 is greater than 8888
      Triple(8754, 6543, ">"),          // Example 21: 8754 is greater than 6543
      Triple(999999, 1000000, "<"),     // Example 22: 999999 is less than 1000000
      Triple(123, 234, "<"),            // Example 23: 123 is less than 234
      Triple(5000000, 1000000, ">"),    // Example 24: 5000000 is greater than 1000000
      Triple(4321, 4322, "<"),          // Example 25: 4321 is less than 4322
      Triple(67890, 12345, ">"),        // Example 26: 67890 is greater than 12345
      Triple(234567, 234567, "="),      // Example 27: 234567 is equal to 234567
      Triple(12000, 15000, "<"),        // Example 28: 12000 is less than 15000
      Triple(789, 123, ">"),            // Example 29: 789 is greater than 123
      Triple(864, 432, ">")             // Example 30: 864 is greater than 432
   )
   val simpleSequences = listOf(
      listOf(1, 2, 3, 4, 5, 6, 7),         // Sequence: 1, 2, 3, 4, 5, 6, 7
      listOf(2, 4, 6, 8, 10, 12, 14),      // Sequence: 2, 4, 6, 8, 10, 12, 14
      listOf(5, 10, 15, 20, 25, 30, 35),   // Sequence: 5, 10, 15, 20, 25, 30, 35
      listOf(10, 20, 30, 40, 50, 60, 70),  // Sequence: 10, 20, 30, 40, 50, 60, 70
      listOf(1, 3, 5, 7, 9, 11, 13),       // Sequence: 1, 3, 5, 7, 9, 11, 13
      listOf(0, 1, 2, 3, 4, 5, 6),         // Sequence: 0, 1, 2, 3, 4, 5, 6
      listOf(5, 6, 7, 8, 9, 10, 11),       // Sequence: 5, 6, 7, 8, 9, 10, 11
      listOf(3, 6, 9, 12, 15, 18, 21),     // Sequence: 3, 6, 9, 12, 15, 18, 21
      listOf(7, 14, 21, 28, 35, 42, 49),   // Sequence: 7, 14, 21, 28, 35, 42, 49
      listOf(4, 8, 12, 16, 20, 24, 28),    // Sequence: 4, 8, 12, 16, 20, 24, 28
      listOf(0, 2, 4, 6, 8, 10, 12),       // Sequence: 0, 2, 4, 6, 8, 10, 12
      listOf(6, 12, 18, 24, 30, 36, 42),   // Sequence: 6, 12, 18, 24, 30, 36, 42
      listOf(1, 5, 9, 13, 17, 21, 25),     // Sequence: 1, 5, 9, 13, 17, 21, 25
      listOf(2, 5, 8, 11, 14, 17, 20),     // Sequence: 2, 5, 8, 11, 14, 17, 20
      listOf(8, 16, 24, 32, 40, 48, 56),   // Sequence: 8, 16, 24, 32, 40, 48, 56
      listOf(0, 5, 10, 15, 20, 25, 30),    // Sequence: 0, 5, 10, 15, 20, 25, 30
      listOf(4, 9, 14, 19, 24, 29, 34),    // Sequence: 4, 9, 14, 19, 24, 29, 34
      listOf(3, 7, 11, 15, 19, 23, 27),    // Sequence: 3, 7, 11, 15, 19, 23, 27
      listOf(1, 2, 4, 6, 8, 10, 12),       // Sequence: 1, 2, 4, 6, 8, 10, 12
      listOf(7, 15, 23, 31, 39, 47, 55),   // Sequence: 7, 15, 23, 31, 39, 47, 55
      listOf(9, 18, 27, 36, 45, 54, 63),   // Sequence: 9, 18, 27, 36, 45, 54, 63
      listOf(10, 15, 20, 25, 30, 35, 40),  // Sequence: 10, 15, 20, 25, 30, 35, 40
      listOf(3, 9, 15, 21, 27, 33, 39),    // Sequence: 3, 9, 15, 21, 27, 33, 39
      listOf(2, 3, 4, 5, 6, 7, 8),         // Sequence: 2, 3, 4, 5, 6, 7, 8
      listOf(1, 4, 7, 10, 13, 16, 19),     // Sequence: 1, 4, 7, 10, 13, 16, 19
      listOf(5, 8, 11, 14, 17, 20, 23),    // Sequence: 5, 8, 11, 14, 17, 20, 23
      listOf(2, 4, 6, 8, 10, 12, 14),      // Sequence: 2, 4, 6, 8, 10, 12, 14
      listOf(6, 12, 18, 24, 30, 36, 42),   // Sequence: 6, 12, 18, 24, 30, 36, 42
      listOf(10, 20, 30, 40, 50, 60, 70),  // Sequence: 10, 20, 30, 40, 50, 60, 70
      listOf(1, 4, 7, 10, 13, 16, 19)      // Sequence: 1, 4, 7, 10, 13, 16, 19
   )
   val proLevelSequences = listOf(
      listOf(3, 6, 9, 12, 15, 18, 21),     // Sequence: Multiples of 3
      listOf(5, 8, 11, 14, 17, 20, 23),    // Sequence: Start at 5, increment by 3
      listOf(2, 4, 8, 16, 32, 64, 128),    // Sequence: Powers of 2
      listOf(10, 15, 21, 28, 36, 45, 55),  // Sequence: Increment by increasing steps (+5, +6, +7...)
      listOf(1, 4, 9, 16, 25, 36, 49),     // Sequence: Squares of numbers (1^2, 2^2, ...)
      listOf(0, 2, 6, 12, 20, 30, 42),     // Sequence: Increment increases by +2 each time
      listOf(4, 12, 20, 28, 36, 44, 52),   // Sequence: Start at 4, increment by 8
      listOf(7, 14, 21, 28, 35, 42, 49),   // Sequence: Multiples of 7
      listOf(3, 7, 11, 15, 19, 23, 27),    // Sequence: Start at 3, increment by 4
      listOf(1, 2, 4, 8, 16, 32, 64),      // Sequence: Doubling each time
      listOf(9, 18, 27, 36, 45, 54, 63),   // Sequence: Multiples of 9
      listOf(11, 22, 33, 44, 55, 66, 77),  // Sequence: Multiples of 11
      listOf(6, 12, 18, 24, 30, 36, 42),   // Sequence: Multiples of 6
      listOf(5, 15, 25, 35, 45, 55, 65),   // Sequence: Start at 5, increment by 10
      listOf(8, 16, 24, 32, 40, 48, 56),   // Sequence: Multiples of 8
      listOf(10, 20, 30, 40, 50, 60, 70),  // Sequence: Multiples of 10
      listOf(12, 24, 36, 48, 60, 72, 84),  // Sequence: Multiples of 12
      listOf(2, 5, 10, 17, 26, 37, 50),    // Sequence: Increment by increasing odd numbers (+3, +5, +7...)
      listOf(7, 14, 28, 35, 42, 49, 63),   // Sequence: Multiples of 7 with a skip (double or single increment alternately)
      listOf(1, 3, 7, 13, 21, 31, 43),     // Sequence: Increment by increasing odd numbers (+2, +4, +6...)
      listOf(2, 8, 18, 32, 50, 72, 98),    // Sequence: Start at 2, increment by doubling (+6, +10, +14...)
      listOf(3, 12, 24, 39, 57, 78, 102),  // Sequence: Increment increases stepwise (+9, +12, +15...)
      listOf(10, 30, 60, 100, 150, 210, 280), // Sequence: Increment increases by +20, +30, +40...
      listOf(5, 11, 19, 29, 41, 55, 71),   // Sequence: Start at 5, increment alternates between +6 and +8
      listOf(2, 3, 5, 8, 12, 17, 23),      // Sequence: Increment increases by +1, +2, +3...
      listOf(15, 30, 45, 70, 85, 110, 135),// Sequence: Increment alternates between +15 and +25
      listOf(4, 6, 10, 18, 34, 66, 130),   // Sequence: Start at 4, each number doubles its increment
      listOf(1, 5, 14, 30, 55, 91, 140),   // Sequence: Cumulative sum of increasing numbers (+4, +9, +16...)
      listOf(10, 25, 50, 85, 130, 185, 250), // Sequence: Increment increases by 15, 25, 35...
      listOf(6, 18, 36, 60, 90, 126, 168)  // Sequence: Multiples of 6 with stepwise increment
   )

   fun getRandomSequence(list: List<List<Int>>): List<Int> {
      return list.random()
   }

   fun getRandomComparison(list:List<Triple<Int,Int,String>>):Triple<Int,Int,String>{
      return list.random()
   }

   fun getRandomQuestion(list: ArrayList<Adding>): Adding {
        if (list.isEmpty()) {
            return Adding(0, 0, 0, 1)
        }
        val randIndex = (0 until list.size).random()
        val randomQues = list[randIndex]
        list.removeAt(randIndex)
        return randomQues
    }
}