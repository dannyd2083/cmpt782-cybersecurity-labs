const comments = [
    { title: "First Comment", body: "This is the first comment." },
    { title: "Second Comment", body: "This is the second comment." },
    { title: "Third Comment", body: "This is another user comment." }
  ];
  export const handler = async (event) => {
    try {
      // Determine the HTTP method (GET or POST)
      const method = event.httpMethod;
      
      if (method === "GET") {
       // Return the current set of comments
          return {
              statusCode: 200,
              body: JSON.stringify(comments),
              headers: {
                  "Content-Type": "application/json",
                  "Access-Control-Allow-Origin": "*"
              }
          };
      } else if (method === "POST") {
          // POST request: Add a new comment
          if (!event.body) {
              return {
                  statusCode: 400,
                  body: JSON.stringify({ message: "Invalid request: POST body cannot be empty." }),
                  headers: {
                      "Content-Type": "application/json",
                      "Access-Control-Allow-Origin": "*"
                  }
              };
          }
  
          const newComment = JSON.parse(event.body);
          
          // new comment has a title and body?
          if (!newComment.title || !newComment.body) {
              return {
                  statusCode: 400,
                  body: JSON.stringify({ message: "Invalid request: Title and body are required." }),
                  headers: {
                      "Content-Type": "application/json",
                      "Access-Control-Allow-Origin": "*"
                  }
              };
          }
          // Add the new comment 
          comments.push(newComment);
          return {
              statusCode: 201,
              body: JSON.stringify({ message: "Comment added successfully.", comments: comments }),
              headers: {
                  "Content-Type": "application/json",
                  "Access-Control-Allow-Origin": "*"
              }
          };
      } else {
          // unsupported HTTP methods
          return {
              statusCode: 405,
              body: JSON.stringify({ message: "Method not allowed." }),
              headers: {
                  "Content-Type": "application/json",
                  "Access-Control-Allow-Origin": "*"
              }
          };
      }
  } catch (error) {
      // unexpected errors
      return {
          statusCode: 500,
          body: JSON.stringify({ message: "Internal Server Error", error: error.message }),
          headers: {
              "Content-Type": "application/json",
              "Access-Control-Allow-Origin": "*"
          }
      };
  }
  };