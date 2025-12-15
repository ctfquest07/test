const mongoose = require('mongoose');

const ChallengeSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'Title is required'],
    trim: true,
    unique: true
  },
  description: {
    type: String,
    required: [true, 'Description is required']
  },
  category: {
    type: String,
    required: [true, 'Category is required'],
    enum: ['web', 'crypto', 'forensics', 'reverse', 'osint', 'misc']
  },
  difficulty: {
    type: String,
    required: [true, 'Difficulty is required'],
    enum: ['Easy', 'Medium', 'Hard', 'Expert']
  },
  points: {
    type: Number,
    required: [true, 'Points are required']
  },
  flag: {
    type: String,
    required: [true, 'Flag is required'],
    select: false // Hide flag in query results by default
  },
  hints: [{
    content: String,
    cost: Number
  }],
  solvedBy: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  isVisible: {
    type: Boolean,
    default: true
  },
  submissionsAllowed: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Virtual for number of solves
ChallengeSchema.virtual('solveCount').get(function() {
  return this.solvedBy ? this.solvedBy.length : 0;
});

// Set toJSON option to include virtuals
ChallengeSchema.set('toJSON', { virtuals: true });
ChallengeSchema.set('toObject', { virtuals: true });

// Create indexes for better performance with multiple users
ChallengeSchema.index({ title: 1 }, { unique: true });
ChallengeSchema.index({ category: 1 }); // For filtering by category
ChallengeSchema.index({ difficulty: 1 }); // For filtering by difficulty
ChallengeSchema.index({ points: 1 }); // For sorting by points
ChallengeSchema.index({ isVisible: 1 }); // For filtering visible challenges
ChallengeSchema.index({ createdAt: 1 }); // For sorting by creation date
ChallengeSchema.index({ solvedBy: 1 }); // For user-specific queries

// Compound indexes for complex queries
ChallengeSchema.index({ category: 1, difficulty: 1 }); // For category + difficulty filtering
ChallengeSchema.index({ isVisible: 1, category: 1 }); // For visible challenges by category
ChallengeSchema.index({ isVisible: 1, points: 1 }); // For visible challenges sorted by points
ChallengeSchema.index({ category: 1, points: 1 }); // For category challenges sorted by points

module.exports = mongoose.model('Challenge', ChallengeSchema);
