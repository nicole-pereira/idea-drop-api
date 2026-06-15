import mongoose from "mongoose";

const ideaSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    title: {
        type: String,
        trim: true
    },
    summary: {
        type: String,
        trim: true
    },
    description: {
        type: String,
    },
    tags: {
        type: [String],
        default: []
    }
}, {
    timestamps: true
});

const Idea = mongoose.model('Idea', ideaSchema);

export default Idea;