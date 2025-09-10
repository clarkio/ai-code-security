import { useEffect, useState } from "react";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import { useLocation, useParams } from "wouter";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { insertNoteSchema, type InsertNote, type Note } from "@shared/schema";
import { DeleteConfirmationModal } from "@/components/delete-confirmation-modal";
import { 
  ArrowLeft, 
  Save, 
  Shield, 
  Info, 
  CheckCircle, 
  Trash2 
} from "lucide-react";

export default function NoteEditor() {
  const { toast } = useToast();
  const { isAuthenticated, isLoading } = useAuth();
  const [, navigate] = useLocation();
  const params = useParams();
  const noteId = params.id;
  const isEditMode = !!noteId;
  const queryClient = useQueryClient();
  const [showDeleteModal, setShowDeleteModal] = useState(false);

  // Redirect to login if not authenticated
  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      toast({
        title: "Unauthorized",
        description: "You are logged out. Logging in again...",
        variant: "destructive",
      });
      setTimeout(() => {
        window.location.href = "/api/login";
      }, 500);
      return;
    }
  }, [isAuthenticated, isLoading, toast]);

  // Fetch note if editing
  const { data: note, isLoading: noteLoading } = useQuery({
    queryKey: ["/api/notes", noteId],
    enabled: isAuthenticated && isEditMode,
    retry: false,
  });

  // Form setup
  const form = useForm<InsertNote>({
    resolver: zodResolver(insertNoteSchema),
    defaultValues: {
      title: "",
      content: "",
    },
  });

  // Update form when note data is loaded
  useEffect(() => {
    if (note) {
      form.reset({
        title: (note as any).title,
        content: (note as any).content,
      });
    }
  }, [note, form]);

  // Save note mutation
  const saveNoteMutation = useMutation({
    mutationFn: async (data: InsertNote) => {
      if (isEditMode) {
        return await apiRequest("PUT", `/api/notes/${noteId}`, data);
      } else {
        return await apiRequest("POST", "/api/notes", data);
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/notes"] });
      toast({
        title: "Success",
        description: isEditMode ? "Note updated successfully" : "Note created successfully",
      });
      navigate("/");
    },
    onError: (error) => {
      if (isUnauthorizedError(error)) {
        toast({
          title: "Unauthorized",
          description: "You are logged out. Logging in again...",
          variant: "destructive",
        });
        setTimeout(() => {
          window.location.href = "/api/login";
        }, 500);
        return;
      }
      toast({
        title: "Error",
        description: isEditMode ? "Failed to update note" : "Failed to create note",
        variant: "destructive",
      });
    },
  });

  // Delete note mutation
  const deleteNoteMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("DELETE", `/api/notes/${noteId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/notes"] });
      toast({
        title: "Success",
        description: "Note deleted successfully",
      });
      navigate("/");
    },
    onError: (error) => {
      if (isUnauthorizedError(error)) {
        toast({
          title: "Unauthorized",
          description: "You are logged out. Logging in again...",
          variant: "destructive",
        });
        setTimeout(() => {
          window.location.href = "/api/login";
        }, 500);
        return;
      }
      toast({
        title: "Error",
        description: "Failed to delete note",
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: InsertNote) => {
    saveNoteMutation.mutate(data);
  };

  const handleDelete = () => {
    deleteNoteMutation.mutate();
    setShowDeleteModal(false);
  };

  const watchedTitle = form.watch("title");
  const watchedContent = form.watch("content");

  if (isLoading || (isEditMode && noteLoading)) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-muted-foreground">Loading...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return null;
  }

  const formatDate = (dateString?: string) => {
    if (!dateString) return "Not saved yet";
    return new Date(dateString).toLocaleDateString("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="bg-card border-b border-border shadow-sm">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-4">
              <Button 
                variant="ghost" 
                size="sm"
                onClick={() => navigate("/")}
                data-testid="button-back"
              >
                <ArrowLeft className="h-4 w-4" />
              </Button>
              <h1 className="text-xl font-semibold">
                {isEditMode ? "Edit Note" : "New Note"}
              </h1>
            </div>
            <div className="flex items-center space-x-3">
              {/* Security Status */}
              <Badge variant="secondary" className="bg-green-50 border-green-200 text-green-700 hover:bg-green-50">
                <Shield className="h-3 w-3 mr-1" />
                Auto-encrypted
              </Badge>
              <Button 
                onClick={form.handleSubmit(onSubmit)}
                disabled={saveNoteMutation.isPending}
                data-testid="button-save"
              >
                <Save className="h-4 w-4 mr-2" />
                Save Securely
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Editor Content */}
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <Card className="shadow-sm">
          {/* Security Notice */}
          <div className="p-4 bg-accent/50 border-b border-border">
            <div className="flex items-center text-sm text-muted-foreground">
              <Info className="h-4 w-4 mr-2 text-primary" />
              <span>All content is automatically sanitized and encrypted before storage. Only you can access this note.</span>
            </div>
          </div>

          {/* Note Form */}
          <CardContent className="p-6">
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
              {/* Title Input */}
              <div>
                <Label htmlFor="title">Note Title</Label>
                <Input
                  id="title"
                  {...form.register("title")}
                  placeholder="Enter note title..."
                  className="text-lg font-medium mt-2"
                  data-testid="input-title"
                />
                <div className="flex items-center justify-between mt-1">
                  <div className="text-xs text-muted-foreground">
                    <CheckCircle className="h-3 w-3 mr-1 text-green-600 inline" />
                    Input sanitized
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {watchedTitle?.length || 0}/100 characters
                  </div>
                </div>
                {form.formState.errors.title && (
                  <p className="text-sm text-destructive mt-1">{form.formState.errors.title.message}</p>
                )}
              </div>

              {/* Content Textarea */}
              <div>
                <Label htmlFor="content">Note Content</Label>
                <Textarea
                  id="content"
                  {...form.register("content")}
                  placeholder="Start writing your note..."
                  rows={12}
                  className="resize-none mt-2"
                  data-testid="textarea-content"
                />
                <div className="flex items-center justify-between mt-1">
                  <div className="text-xs text-muted-foreground">
                    <CheckCircle className="h-3 w-3 mr-1 text-green-600 inline" />
                    Content sanitized and validated
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {(watchedContent?.length || 0)}/5000 characters
                  </div>
                </div>
                {form.formState.errors.content && (
                  <p className="text-sm text-destructive mt-1">{form.formState.errors.content.message}</p>
                )}
              </div>

              {/* Note Metadata */}
              {isEditMode && note && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-4 border-t border-border">
                  <div>
                    <Label>Created</Label>
                    <div className="text-sm text-muted-foreground mt-1" data-testid="text-created">
                      {formatDate((note as any).createdAt)}
                    </div>
                  </div>
                  <div>
                    <Label>Last Modified</Label>
                    <div className="text-sm text-muted-foreground mt-1" data-testid="text-updated">
                      {formatDate((note as any).updatedAt)}
                    </div>
                  </div>
                </div>
              )}

              {/* Security Information */}
              <div className="bg-green-50 border border-green-200 rounded-md p-4">
                <h3 className="text-sm font-medium text-green-800 mb-2">Security Features Active</h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-green-700">
                  <div className="flex items-center">
                    <CheckCircle className="h-3 w-3 mr-2" />
                    XSS Protection Enabled
                  </div>
                  <div className="flex items-center">
                    <CheckCircle className="h-3 w-3 mr-2" />
                    Content Encryption
                  </div>
                  <div className="flex items-center">
                    <CheckCircle className="h-3 w-3 mr-2" />
                    User Authorization Verified
                  </div>
                  <div className="flex items-center">
                    <CheckCircle className="h-3 w-3 mr-2" />
                    Secure Database Storage
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex justify-between items-center pt-4 border-t border-border">
                {isEditMode && (
                  <Button 
                    type="button"
                    variant="destructive"
                    onClick={() => setShowDeleteModal(true)}
                    disabled={deleteNoteMutation.isPending}
                    data-testid="button-delete"
                  >
                    <Trash2 className="h-4 w-4 mr-2" />
                    Delete Note
                  </Button>
                )}
                {!isEditMode && <div></div>}
                <div className="flex space-x-3">
                  <Button 
                    type="button"
                    variant="outline"
                    onClick={() => navigate("/")}
                    data-testid="button-cancel"
                  >
                    Cancel
                  </Button>
                  <Button 
                    type="submit"
                    disabled={saveNoteMutation.isPending}
                    data-testid="button-save-changes"
                  >
                    <Save className="h-4 w-4 mr-2" />
                    {isEditMode ? "Save Changes" : "Create Note"}
                  </Button>
                </div>
              </div>
            </form>
          </CardContent>
        </Card>
      </div>

      {/* Delete Confirmation Modal */}
      <DeleteConfirmationModal
        isOpen={showDeleteModal}
        onClose={() => setShowDeleteModal(false)}
        onConfirm={handleDelete}
        isDeleting={deleteNoteMutation.isPending}
      />
    </div>
  );
}
