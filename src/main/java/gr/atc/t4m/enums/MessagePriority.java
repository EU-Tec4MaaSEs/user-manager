package gr.atc.t4m.enums;

public enum MessagePriority {
    LOW("Low"),
    MID("Mid"),
    HIGH("High");

    private final String priority;

    MessagePriority(final String priority) {
        this.priority = priority;
    }

    @Override
    public String toString() {
        return priority;
    }
}
