package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
)

type LogEntry struct {
	Req struct {
		URL        string            `json:"url"`
		QSParams   string            `json:"qs_params"`
		Headers    map[string]string `json:"headers"`
		ReqBodyLen int               `json:"req_body_len"`
	} `json:"req"`
	Rsp struct {
		StatusClass string `json:"status_class"`
		RspBodyLen  int    `json:"rsp_body_len"`
	} `json:"rsp"`
}

type SuspiciousActivity struct {
	UserID      string
	AccessedID  string
	Endpoint    string
	Description string
}

func main() {
	// Get the log file name from the user input
	fmt.Println("Enter the access log file name:")
	var logFileName string
	fmt.Scanln(&logFileName)

	// Read the log file content
	content, err := ioutil.ReadFile(logFileName)
	if err != nil {
		log.Fatalf("Error reading log file: %v", err)
	}

	// Split content by newlines, as each log entry is on a new line
	logEntries := strings.Split(string(content), "\n")

	var suspiciousActivities []SuspiciousActivity

	// Expected user_id (in a real scenario, this would be dynamically determined)
	expectedUserID := "12345" // This would typically come from the logged-in user's session/JWT claim

	// Process each log entry
	for _, entry := range logEntries {
		if entry == "" {
			continue
		}

		// Parse the log entry
		var logEntry LogEntry
		err := json.Unmarshal([]byte(entry), &logEntry)
		if err != nil {
			log.Printf("Error parsing log entry: %v", err)
			continue
		}

		// Check for BOLA patterns in the query parameters (e.g., user_id)
		if strings.Contains(logEntry.Req.QSParams, "user_id=") {
			// Extract the user_id from the URL query parameters
			qsParams := logEntry.Req.QSParams
			userID := extractUserID(qsParams)

			// Check if the user_id matches the expected user ID
			if userID != expectedUserID {
				suspiciousActivities = append(suspiciousActivities, SuspiciousActivity{
					UserID:      expectedUserID,
					AccessedID:  userID,
					Endpoint:    logEntry.Req.URL,
					Description: "Potential BOLA attack - user trying to access another user's resource",
				})
			}
		}
	}

	// Output any suspicious activities
	if len(suspiciousActivities) > 0 {
		fmt.Println("Potential BOLA attacks detected:")
		for _, activity := range suspiciousActivities {
			fmt.Printf("User ID: %s attempted to access user ID: %s at endpoint %s\n", activity.UserID, activity.AccessedID, activity.Endpoint)
			fmt.Println("Description:", activity.Description)
		}
	} else {
		fmt.Println("No suspicious activity detected.")
	}
}

// Helper function to extract user_id from query parameters
func extractUserID(qsParams string) string {
	// Simple parsing logic to extract the user_id value
	// Assuming user_id is in the format "user_id=<value>"
	parts := strings.Split(qsParams, "&")
	for _, part := range parts {
		if strings.HasPrefix(part, "user_id=") {
			// Return the part after "user_id="
			return strings.TrimPrefix(part, "user_id=")
		}
	}
	return ""
}
