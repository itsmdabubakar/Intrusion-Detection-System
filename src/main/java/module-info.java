module com.example.intrusiondetectionsystem {
    requires javafx.controls;
    requires javafx.fxml;


    opens com.example.intrusiondetectionsystem to javafx.fxml;
    exports com.example.intrusiondetectionsystem;
}