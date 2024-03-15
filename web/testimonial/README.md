solved by Kibov and makider

chall files:
[web_testimonial.zip](./web_testimonial.zip)

this webserver is written in go

in this webserver you can send testimonials with your name

after a bit of looking around i found out that your name gets written as the file name containing your testimonial in a folder in the file system. 

This might be a arbitrary write.

but the input is unfortunately sanitized with this function

```go
func (c *Client) SendTestimonial(customer, testimonial string) error {
    ctx := context.Background()
    // Filter bad characters.
    for _, char := range []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|", "."} {
        customer = strings.ReplaceAll(customer, char, "")
    }

    _, err := c.SubmitTestimonial(ctx, &pb.TestimonialSubmission{Customer: customer, Testimonial: testimonial})
    return err
}
```

after further looking around we found out that the server communicates to a grpc server.

we can just directly communicate to the grpc server thus bypassing the filter.

to do that we used the google grpc python module.

then we modified the username to be ../../view/home/index.templ

and the testimonial to be the whole index.templ with some code the include the flag like this /flag*

![alt text](image.png)

and we did it!

`HTB{w34kly_t35t3d_t3mplate5}`